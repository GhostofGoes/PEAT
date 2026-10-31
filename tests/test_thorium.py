"""
Tests for the Thorium client (peat.thorium) and uploading files with
"peat import". HTTP requests are mocked with requests-mock.
"""

import base64
import hashlib
import json
from email.parser import BytesParser
from email.policy import HTTP

import pytest
import requests

from peat import config, consts, state
from peat.api.import_api import import_results, import_run_to_thorium, thorium_tags
from peat.run_results import RunResults
from peat.thorium import MultipartFileBody, Thorium, clean_text

URL = "https://thorium.example.com"
API = f"{URL}/api"
TOKEN = "my-secret-token"
AUTH = f"token {base64.b64encode(TOKEN.encode()).decode()}"


def parse_multipart(body: bytes, content_type: str) -> list[tuple[str, str | None, bytes]]:
    """Parse a multipart/form-data body into (name, filename, content)."""
    msg = BytesParser(policy=HTTP).parsebytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body
    )
    return [
        (
            part.get_param("name", header="content-disposition"),
            part.get_filename(),
            part.get_payload(decode=True),
        )
        for part in msg.iter_parts()
    ]


@pytest.fixture
def thorium_env(monkeypatch):
    monkeypatch.setenv("PEAT_THORIUM_TOKEN", TOKEN)


@pytest.fixture
def isolated(mocker, tmp_path):
    mocker.patch.dict(
        config["runtime_configs"],
        {
            "ELASTIC_DIR": None,
            "LOG_DIR": None,
            "DEVICE_DIR": None,
            "SUMMARIES_DIR": None,
            "RUN_DIR": tmp_path / "import-run",
            "ELASTIC_SERVER": None,
            "DRY_RUN": False,
        },
    )
    mocker.patch.dict(state["runtime_configs"], {"error": False, "elastic": None})


@pytest.fixture
def run_dir(tmp_path):
    run_dir = tmp_path / "pull_default-config_2026-10-31_05-11-49_179343190989"
    dev_dir = run_dir / "devices" / "192.0.2.10"
    (dev_dir / "configs").mkdir(parents=True)
    (dev_dir / "device-data-summary.json").write_text(
        json.dumps(
            {
                "id": "192.0.2.10",
                "ip": "192.0.2.10",
                "type": "Relay\x1b[31m",
                "description": {"vendor": {"id": "SEL", "name": "Schweitzer"}, "model": "351"},
            }
        )
    )
    (dev_dir / "device-data-full.json").write_text("{}")
    (dev_dir / "SET_1.TXT").write_bytes(b"[1]\nRID=relay1\n")
    (dev_dir / "configs" / "firmware.bin").write_bytes(bytes(range(256)) * 10)
    (dev_dir / "empty.txt").write_bytes(b"")
    (run_dir / "summaries").mkdir()
    (run_dir / "summaries" / "pull-summary.json").write_text('{"peat_run_id": "179343190989"}')
    return run_dir


def test_url_handling(thorium_env):  # noqa: ARG001
    th = Thorium("https://user:p%40ss@thorium.example.com:8443/api/", groups=["g", ""])
    assert th.safe_url == "https://thorium.example.com:8443"
    assert th.api_url == "https://thorium.example.com:8443/api"
    assert th._username == "user"
    assert th._password == "p@ss"
    assert "p@ss" not in repr(th)
    assert str(th) == "thorium.example.com:8443"
    assert th.groups == ["g"]

    assert Thorium("thorium.local").safe_url == "https://thorium.local"
    assert Thorium("http://[2001:db8::1]:80/").host == "[2001:db8::1]:80"


@pytest.mark.parametrize(
    "bad",
    [
        "ftp://user:secretpw@thorium",
        "https://",
        "https://user:secretpw@host:abc/",
        "https://user:secretpw@host:99999/",
        "https://user:secretpw@[::1/",
    ],
)
def test_invalid_url(bad):
    # Invalid URLs raise a PeatError (not ValueError), without the password
    with pytest.raises(consts.PeatError, match="Invalid Thorium URL") as exc_info:
        Thorium(bad)
    assert "secretpw" not in str(exc_info.value)


def test_groups():
    assert Thorium(URL, groups="ot-team, ics").groups == ["ot-team", "ics"]
    assert Thorium(URL, groups=["ot-team,ics", "lab", "ics", ""]).groups == [
        "ot-team",
        "ics",
        "lab",
    ]
    assert Thorium(URL, groups=None).groups == []


def test_groups_from_environment(monkeypatch, mocker):
    # List options set from strings are split on commas, not into characters
    # Restored after the test. Runtime values (e.g. from other tests) take precedence.
    mocker.patch.dict(config["env_configs"])
    mocker.patch.dict(config["runtime_configs"])
    config["runtime_configs"].pop("THORIUM_GROUPS", None)
    monkeypatch.setenv("PEAT_THORIUM_GROUPS", "ot-team,ics")
    config.load_from_environment()
    assert config["env_configs"]["THORIUM_GROUPS"] == ["ot-team", "ics"]
    assert config.THORIUM_GROUPS == ["ot-team", "ics"]


def test_clean_text():
    assert clean_text("a\r\nb\x00c\x1b[1m") == "a  b c [1m"
    assert clean_text("x" * 1000) == "x" * 256
    assert clean_text(123) == "123"


def test_connect(requests_mock, thorium_env, caplog):  # noqa: ARG001
    requests_mock.get(f"{API}/users/whoami", json={"username": "analyst", "groups": ["ot"]})
    th = Thorium(URL, groups=["ot", "other"])
    user = th.connect()
    assert user["username"] == "analyst"
    assert requests_mock.last_request.headers["Authorization"] == AUTH
    assert "isn't a member of the group(s) ['other']" in caplog.text
    assert TOKEN not in caplog.text

    with pytest.raises(consts.PeatError, match="No Thorium groups"):
        Thorium(URL).connect()


def test_connect_errors(requests_mock, monkeypatch):
    monkeypatch.delenv("PEAT_THORIUM_TOKEN", raising=False)
    with pytest.raises(consts.PeatError, match="PEAT_THORIUM_TOKEN"):
        Thorium(URL, groups=["ot"]).connect()

    requests_mock.get(f"{API}/users/whoami", status_code=401, text="bad\ntoken")
    with pytest.raises(consts.PeatError, match="HTTP 401"):
        Thorium(URL, groups=["ot"], token="x").connect()

    requests_mock.get(f"{API}/users/whoami", text="not json")
    with pytest.raises(consts.PeatError, match="Invalid JSON"):
        Thorium(URL, groups=["ot"], token="x").connect()

    requests_mock.get(f"{API}/users/whoami", exc=requests.ConnectionError("refused"))
    with pytest.raises(consts.PeatError, match="failed"):
        Thorium(URL, groups=["ot"], token="x").connect()


def test_authenticate_with_password(requests_mock, monkeypatch):
    monkeypatch.delenv("PEAT_THORIUM_TOKEN", raising=False)
    requests_mock.post(
        f"{API}/users/auth",
        json={"Authed": {"token": "abc", "expires": "2026-12-01T00:00:00Z"}},
    )
    requests_mock.get(f"{API}/users/whoami", json={"username": "u", "groups": ["ot"]})
    th = Thorium("https://u:pw@thorium.example.com/", groups=["ot"])
    th.connect()

    auth_req, whoami_req = requests_mock.request_history
    assert auth_req.headers["Authorization"] == f"basic {base64.b64encode(b'u:pw').decode()}"
    assert whoami_req.headers["Authorization"] == f"token {base64.b64encode(b'abc').decode()}"

    # Older response format, and email verification required
    requests_mock.post(f"{API}/users/auth", json={"token": "def"})
    assert Thorium("https://u:pw@thorium.example.com/").authenticate() == "def"
    requests_mock.post(f"{API}/users/auth", json={"VerifyEmail": "u@example.com"})
    with pytest.raises(consts.PeatError, match="verified"):
        Thorium("https://u:pw@thorium.example.com/").authenticate()
    requests_mock.post(f"{API}/users/auth", json=[])
    with pytest.raises(consts.PeatError, match="Unexpected"):
        Thorium("https://u:pw@thorium.example.com/").authenticate()


def test_upload_file_already_submitted(requests_mock, thorium_env, tmp_path):  # noqa: ARG001
    # Thorium responds with 409 Conflict if the same user already submitted the
    # file with the same name, description and groups (it still adds the tags)
    path = tmp_path / "SET_1.TXT"
    path.write_bytes(b"data")
    requests_mock.post(f"{API}/files/", status_code=409, text="conflict")
    assert Thorium(URL, groups=["ot"]).upload_file(path) is None


def test_multipart_body(tmp_path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00\x01data" * 1000)
    # The name is passed separately, since Windows doesn't allow " or CR/LF in file names
    hostile_name = 'we"ird\r\nname.bin'
    body = MultipartFileBody([("groups", "ot"), ("tags[a]", "b c")], "data", hostile_name, path)
    content = b""
    while chunk := body.read(333):  # Small reads span the parts
        content += chunk
    body.close()
    assert len(content) == len(body)
    parts = parse_multipart(content, body.content_type)
    assert parts[0] == ("groups", None, b"ot")
    assert parts[1] == ("tags[a]", None, b"b c")
    name, filename, data = parts[2]
    assert name == "data"
    assert filename == "we_ird  name.bin"
    assert data == path.read_bytes()


def test_upload_file(requests_mock, thorium_env, tmp_path):  # noqa: ARG001
    path = tmp_path / "firmware.bin"
    path.write_bytes(b"\xff" * 5000)
    captured = {}

    def _upload(request, context):  # noqa: ARG001
        captured["body"] = request.body.read()
        captured["headers"] = request.headers
        return {"sha256": "x", "sha1": "y", "md5": "z", "id": "uuid"}

    requests_mock.post(f"{API}/files/", json=_upload)
    th = Thorium(URL, groups=["ot", "ics"])
    result = th.upload_file(
        path, tags={"ip": "192.0.2.1", "multi": ["a", "b"], "empty": ""}, description="desc"
    )
    assert result["id"] == "uuid"
    assert captured["headers"]["Authorization"] == AUTH
    assert int(captured["headers"]["Content-Length"]) == len(captured["body"])
    parts = parse_multipart(captured["body"], captured["headers"]["Content-Type"])
    fields = [(n, d.decode()) for n, f, d in parts if f is None]
    assert fields == [
        ("description", "desc"),
        ("groups", "ot"),
        ("groups", "ics"),
        ("tags[ip]", "192.0.2.1"),
        ("tags[multi]", "a"),
        ("tags[multi]", "b"),
        ("trigger_depth", "0"),
    ]
    assert parts[-1][1:] == ("firmware.bin", path.read_bytes())

    requests_mock.post(f"{API}/files/", status_code=500, text="error")
    with pytest.raises(consts.PeatError, match="HTTP 500"):
        th.upload_file(path)
    with pytest.raises(consts.PeatError, match="No Thorium groups"):
        Thorium(URL).upload_file(path)


def test_thorium_tags(run_dir):
    results = RunResults.open(run_dir)
    dev = results.devices()[0]
    tags = thorium_tags(results, "179343190989", dev, dev.load_summary())
    assert tags == {
        "source": "PEAT",
        "peat_run_id": "179343190989",
        "peat_run_name": run_dir.name,
        "peat_device_id": "192.0.2.10",
        "peat_device_ip": "192.0.2.10",
        "peat_device_type": "Relay\x1b[31m",  # Cleaned when uploading
        "peat_device_vendor": "Schweitzer",
        "peat_device_model": "351",
    }
    # Malformed or missing summary
    assert thorium_tags(results, None, dev, {"description": "x", "id": 5}) == {
        "source": "PEAT",
        "peat_run_name": run_dir.name,
        "peat_device_id": "192.0.2.10",
    }


class FakeThorium:
    """
    Mock of Thorium's file upload API, with the same duplicate handling as the
    server (api/src/models/backends/db/files.rs): a new submission is created
    unless the same user submitted the same file with the same name,
    description and groups, in which case the tags are added and the
    response is 409 Conflict.
    """

    def __init__(self, requests_mock) -> None:
        self.submissions: list[dict] = []
        self.tags: dict[str, set[tuple[str, str]]] = {}
        requests_mock.post(f"{API}/files/", json=self._upload)

    def _upload(self, request, context):
        parts = parse_multipart(request.body.read(), request.headers["Content-Type"])
        fields: dict[str, list[str]] = {}
        for name, filename, data in parts:
            if filename is None:
                fields.setdefault(name, []).append(data.decode())
        name, data = parts[-1][1], parts[-1][2]
        sha256 = hashlib.sha256(data).hexdigest()
        sub = {
            "sha256": sha256,
            "name": name,
            "description": fields.get("description", [""])[0],
            "groups": sorted(fields["groups"]),
            "fields": fields,
        }
        tags = {(k[5:-1], v) for k, vals in fields.items() if k.startswith("tags[") for v in vals}
        self.tags.setdefault(sha256, set()).update(tags)
        key = ("sha256", "name", "description", "groups")
        if any(all(other[k] == sub[k] for k in key) for other in self.submissions):
            context.status_code = 409
            return {"error": sha256}
        self.submissions.append(sub)
        return {"sha256": sha256, "id": f"uuid-{len(self.submissions)}"}


def test_import_run_to_thorium(requests_mock, thorium_env, run_dir):  # noqa: ARG001
    fake = FakeThorium(requests_mock)

    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert (res.files_found, res.files_uploaded, res.files_skipped, res.files_failed) == (
        3,
        2,
        1,  # Empty file
        0,
    )
    by_name = {sub["name"]: sub["fields"] for sub in fake.submissions}
    assert sorted(by_name) == ["SET_1.TXT", "firmware.bin"]
    upload = by_name["SET_1.TXT"]
    assert upload["tags[peat_file_path]"] == ["SET_1.TXT"]
    assert upload["tags[peat_device_ip]"] == ["192.0.2.10"]
    assert upload["tags[peat_device_type]"] == ["Relay [31m"]
    assert upload["tags[peat_run_id]"] == ["179343190989"]
    assert upload["groups"] == ["ot"]
    assert "collected by PEAT from device '192.0.2.10'" in upload["description"][0]
    assert by_name["firmware.bin"]["tags[peat_file_path]"] == ["configs/firmware.bin"]

    # Importing the run again doesn't create duplicate submissions
    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert (res.files_uploaded, res.files_skipped, res.files_failed) == (0, 3, 0)
    assert not res.failed
    assert len(fake.submissions) == 2

    # Files that are already in Thorium are uploaded to new groups
    res = import_run_to_thorium(Thorium(URL, groups=["ics"]), RunResults.open(run_dir))
    assert res.files_uploaded == 2
    assert len(fake.submissions) == 4


def test_import_run_to_thorium_same_file_on_devices(requests_mock, thorium_env, run_dir):  # noqa: ARG001
    # The same file on two devices is submitted for each device, with its tags
    other = run_dir / "devices" / "192.0.2.11"
    other.mkdir()
    (other / "device-data-summary.json").write_text('{"id": "192.0.2.11", "ip": "192.0.2.11"}')
    (other / "SET_1.TXT").write_bytes((run_dir / "devices/192.0.2.10/SET_1.TXT").read_bytes())
    fake = FakeThorium(requests_mock)

    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert (res.files_uploaded, res.files_failed) == (3, 0)
    set_subs = [sub for sub in fake.submissions if sub["name"] == "SET_1.TXT"]
    assert [sub["fields"]["tags[peat_device_ip]"] for sub in set_subs] == [
        ["192.0.2.10"],
        ["192.0.2.11"],
    ]
    assert {("peat_device_ip", "192.0.2.10"), ("peat_device_ip", "192.0.2.11")} <= fake.tags[
        set_subs[0]["sha256"]
    ]


def test_import_run_to_thorium_failures(requests_mock, thorium_env, run_dir):  # noqa: ARG001
    requests_mock.post(f"{API}/files/", status_code=403)
    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert (res.files_uploaded, res.files_failed) == (0, 2)
    assert res.failed


def test_import_run_to_thorium_not_peat_device_dir(requests_mock, thorium_env, run_dir, caplog):  # noqa: ARG001
    # Directories without PEAT's device data files aren't uploaded
    other = run_dir / "devices" / "not-a-device"
    other.mkdir()
    (other / "notes.txt").write_text("private")
    fake = FakeThorium(requests_mock)

    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert res.files_found == 3
    assert "notes.txt" not in {sub["name"] for sub in fake.submissions}
    assert "doesn't have PEAT's device data files" in caplog.text


def _secret_home(tmp_path):
    """Files outside of the run directory, that must never be uploaded."""
    home = tmp_path / "home"
    (home / "analyst" / ".ssh").mkdir(parents=True)
    (home / "analyst" / ".ssh" / "id_rsa").write_text("PRIVATE KEY")
    (home / "analyst" / "device-data-summary.json").write_text("{}")
    return home


def test_import_run_to_thorium_devices_symlink(requests_mock, thorium_env, tmp_path):  # noqa: ARG001
    home = _secret_home(tmp_path)
    run_dir = tmp_path / "evil_run_179343190989"
    (run_dir / "summaries").mkdir(parents=True)
    try:
        (run_dir / "devices").symlink_to(home, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks aren't supported")
    fake = FakeThorium(requests_mock)

    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert res.files_found == 0
    assert not fake.submissions


def test_import_run_to_thorium_device_symlinks(requests_mock, thorium_env, run_dir, tmp_path):  # noqa: ARG001
    home = _secret_home(tmp_path)
    dev_dir = run_dir / "devices" / "192.0.2.10"
    try:
        (dev_dir / "id_rsa").symlink_to(home / "analyst" / ".ssh" / "id_rsa")
        (dev_dir / "ssh").symlink_to(home / "analyst" / ".ssh", target_is_directory=True)
        (run_dir / "devices" / "evil").symlink_to(home / "analyst", target_is_directory=True)
    except OSError:
        pytest.skip("symlinks aren't supported")
    fake = FakeThorium(requests_mock)

    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), RunResults.open(run_dir))
    assert res.files_found == 3
    assert sorted(sub["name"] for sub in fake.submissions) == ["SET_1.TXT", "firmware.bin"]


def test_import_run_to_thorium_configured_device_dir(requests_mock, thorium_env, tmp_path):  # noqa: ARG001
    # DEVICE_DIR in the (untrusted) saved configuration that's outside the run directory
    home = _secret_home(tmp_path)
    run_dir = tmp_path / "evil_run_179343190989"
    (run_dir / "summaries").mkdir(parents=True)
    (run_dir / "peat_metadata").mkdir()
    (run_dir / "peat_metadata" / "peat_configuration.yaml").write_text(
        f"device_dir: {home.as_posix()}\nrun_dir: {run_dir.as_posix()}\n"
    )
    fake = FakeThorium(requests_mock)

    results = RunResults.open(run_dir)
    res = import_run_to_thorium(Thorium(URL, groups=["ot"]), results)
    assert res.files_found == 0
    assert not fake.submissions
    assert any("outside" in err for err in results.load_errors)


def test_import_results_thorium(requests_mock, thorium_env, run_dir, isolated, mocker):  # noqa: ARG001
    mocker.patch.dict(
        config["runtime_configs"],
        {"THORIUM_URL": URL, "THORIUM_GROUPS": ["ot"], "THORIUM_VERIFY_TLS": False},
    )
    requests_mock.get(f"{API}/users/whoami", json={"username": "u", "groups": ["ot"]})
    requests_mock.post(f"{API}/files/", json={"sha256": "x"})

    summary = import_results([run_dir])
    assert summary["import_targets"] == [f"Thorium ({URL})"]
    assert summary["runs"][0]["files_uploaded"] == 2
    assert summary["num_runs_failed"] == 0
    assert requests_mock.request_history[-1].verify is False

    # Failure to connect stops the import before anything is uploaded
    requests_mock.reset_mock()
    requests_mock.get(f"{API}/users/whoami", status_code=401)
    assert import_results([run_dir]) is None
    assert [r.method for r in requests_mock.request_history] == ["GET"]

    # Dry run doesn't connect
    requests_mock.reset_mock()
    summary = import_results([run_dir], dry_run=True)
    assert summary["runs"][0]["files_found"] == 3
    assert not requests_mock.request_history
