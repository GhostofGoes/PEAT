"""
Tests for pushing settings to SEL relays (``peat push -d selrelay``):
``peat/modules/sel/sel_push.py``, ``SELRelay._push()``, and the settings file
conversions in ``relay_parse.py``.

The relays are fakes of the FTP server on a relay (a stand-in for
``ftplib.FTP``), with the files in memory. The real SEL-710 RDB file and
streams are from data_files/relay/ (sources and licenses are in the README.md
there). Other settings files are short inline strings in the formats shown in
the "Virtual File Interface" sections of the SEL-351S (Section 10) and SEL-421
(Section R.5) instruction manuals. The upload procedure (write each
SET_<class>.TXT, then read ERR.TXT, which is empty if the settings were
accepted) is from the same sections.
"""

import ftplib
import hashlib
import shutil
from pathlib import Path, PurePosixPath

import pytest

from peat import ParseError, SELRelay, config, datastore
from peat.modules.sel import sel_push
from peat.modules.sel.relay_parse import (
    combine_settings_files,
    normalize_settings_file,
    rdb_relay_settings_files,
    rdb_relay_to_set_all,
    rdb_to_settings_files,
    read_rdb_streams,
    settings_class_files,
    sort_settings_filenames,
    split_set_all,
)
from peat.modules.sel.sel_push import (
    PushFile,
    PushInputError,
    check_push_input,
    has_placeholder_info,
    order_for_upload,
    prepare_push,
    replace_info_section,
    select_rdb_relay,
)

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"
RDB_PATH = RELAY_DIR / "sel-710_Relay710.rdb"
STREAMS_DIR = RELAY_DIR / "sel-710_rdb_streams"
RDB_RELAY = "New Settings 2"

#: SEL-710 classes in the order of [CLASSES] in Misc/Cfg.txt
SEL710_FILES = [
    "SET_1.TXT",
    "SET_2.TXT",
    "SET_3.TXT",
    "SET_L1.TXT",
    "SET_L2.TXT",
    "SET_L3.TXT",
    "SET_G.TXT",
    "SET_PF.TXT",
    "SET_P1.TXT",
    "SET_P2.TXT",
    "SET_P3.TXT",
    "SET_P4.TXT",
    "SET_F.TXT",
    "SET_R.TXT",
    "SET_M.TXT",
]

#: The order PEAT uploads them: the port settings last, Port 1 (Ethernet, with IPADDR) at the end
SEL710_UPLOAD_ORDER = [
    "SET_1.TXT",
    "SET_2.TXT",
    "SET_3.TXT",
    "SET_L1.TXT",
    "SET_L2.TXT",
    "SET_L3.TXT",
    "SET_G.TXT",
    "SET_F.TXT",
    "SET_R.TXT",
    "SET_M.TXT",
    "SET_PF.TXT",
    "SET_P2.TXT",
    "SET_P3.TXT",
    "SET_P4.TXT",
    "SET_P1.TXT",
]

#: A real (not placeholder) [INFO] for the fake SEL-710
SEL710_INFO = (
    b"[INFO]\r\n"
    b"RELAYTYPE=SEL-710\r\n"
    b"FID=SEL-710-R411-V0-Z008004-D20230101\r\n"
    b"BFID=SLBT-710-R101-V0-Z007004-D20230101\r\n"
    b"PARTNO=071001A5X6X71821210\r\n"
)

#: SEL-351S CFG.TXT, in the format of Figure 10.7 of the SEL-351S
#: instruction manual (the class checksums are made up)
SEL351S_INFO = (
    b"[INFO]\r\n"
    b"RELAYTYPE=0351S\r\n"
    b"FID=SEL-351S-7-R516-V2-Z106105-D20190111\r\n"
    b"BFID=SLBT-3CF1-R200-V0-Z100100-D20120321\r\n"
    b"PARTNO=0351S7XHD3J5442\r\n"
)
SEL351S_CFG = SEL351S_INFO + (
    b"[CLASSES]\r\n"
    b'"1","Group 1","SET_1.TXT","30C0490A"\r\n'
    b'"G","Global","SET_G.TXT","C2B2FE98"\r\n'
    b'"L1","Logic 1","SET_L1.TXT","00340302"\r\n'
    b'"P1","Port 1","SET_P1.TXT","939DC3DD"\r\n'
    b'"P5","Port 5","SET_P5.TXT","E665D08E"\r\n'
    b"[STORAGE]\r\n"
    b'"SWCFG.ZIP"\r\n'
)
SEL351S_FILES = {
    "SET_1.TXT": SEL351S_INFO + b'[1]\r\nRID,"FEEDER 7"\r\nTID,"STATION A"\r\nCTR,"120"\r\n',
    "SET_G.TXT": SEL351S_INFO + b'[G]\r\nDATE_F,"MDY"\r\n',
    "SET_L1.TXT": SEL351S_INFO + b'[L1]\r\nTR,"M1P + Z1G + 51PT"\r\n',
    "SET_P1.TXT": SEL351S_INFO + b'[P1]\r\nPROTO,"SEL"\r\nSPEED,"9600"\r\n',
    "SET_P5.TXT": SEL351S_INFO + b'[P5]\r\nIPADDR,"192.0.2.30"\r\nSUBNETM,"255.255.255.0"\r\n',
}

#: SEL-421 settings files begin with [INFO], [IOBOARDS], and [COMCARDS] sections, like
#: the sample SET_G1.TXT (Figure 3.4, "Oscillography") and SET_P5.TXT ("Direct Networking
#: Example") in the SEL-421 Applications Handbook. RELAYTYPE=SEL is from the SET_P5.TXT
#: sample, and the [IOBOARDS] line is from the SET_G1.TXT sample. The other values are made up.
SEL421_HEADER = (
    b"[INFO]\r\n"
    b"RELAYTYPE=SEL\r\n"
    b"FID=SEL-421-R120-V0-Z009005-D20111215\r\n"
    b"BFID=SLBT-4XX-R101-V0-Z001001-D20100101\r\n"
    b"PARTNO=0421X1XXXXXXXXX\r\n"
    b"[IOBOARDS]\r\n"
    b", , , 8, 8, 0, 0, 1\r\n"
    b"[COMCARDS]\r\n"
    b", SEL-2701-R100-V0-Z000000-D20100101, SLBT-2701-R100-V0-Z000000-D20100101, 1\r\n"
)
#: CFG.TXT of the fake SEL-421 (the RELAYTYPE and class checksums are made up)
SEL421_CFG = (
    b"[INFO]\r\n"
    b"RELAYTYPE=0421\r\n"
    b"FID=SEL-421-R120-V0-Z009005-D20111215\r\n"
    b"[CLASSES]\r\n"
    b'S1,"Group 1","\\SETTINGS\\SET_S1.TXT","30C0490A"\r\n'
    b'G1,"Global","\\SETTINGS\\SET_G1.TXT","C2B2FE98"\r\n'
    b'P5,"Port 5","\\SETTINGS\\SET_P5.TXT","E665D08E"\r\n'
)
SEL421_FILES = {
    "SET_S1.TXT": SEL421_HEADER + b'[S1]\r\n"RID","FEEDER 9"\r\n"TID","STATION B"\r\n',
    "SET_G1.TXT": SEL421_HEADER + b'[G1]\r\n"SID","STATION B"\r\n"NFREQ",60\r\n',
    "SET_P5.TXT": SEL421_HEADER + b'[P5]\r\n"IPADDR","192.0.2.40"\r\n"FTPSERV","Y"\r\n',
}


def _hashes(data: bytes) -> dict[str, str]:
    return {
        algo: getattr(hashlib, algo)(data).hexdigest().upper()
        for algo in ["md5", "sha1", "sha256", "sha512"]
    }


def _streams() -> dict[str, bytes]:
    """The SEL-710 streams, keyed by their path in the relay's storage in the RDB."""
    return {
        path.relative_to(STREAMS_DIR).as_posix(): path.read_bytes()
        for path in STREAMS_DIR.rglob("*")
        if path.is_file()
    }


def _stream_for(name: str) -> bytes:
    return (STREAMS_DIR / f"set_{name[4:-4]}.txt").read_bytes()


class Clock:
    """Fake clock for the push: sleep() moves the time forward."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps = []  # type: list[float]

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


@pytest.fixture(autouse=True)
def clock(mocker) -> Clock:
    fake = Clock()
    mocker.patch.object(sel_push, "sleep", fake.sleep)
    mocker.patch.object(sel_push, "monotonic", fake.monotonic)
    return fake


# ---------------------------------------------------------------------------
# Fake relay FTP server
# ---------------------------------------------------------------------------


class FakeRelay:
    """
    A SEL relay's FTP server. Files are keyed by their path, e.g. "CFG.TXT"
    or "SETTINGS/SET_1.TXT". The settings files are in ``settings_dir``,
    with the ERR.TXT for them.
    """

    def __init__(
        self,
        files: dict[str, bytes],
        settings_dir: str = "",
        user: str = "FTPUSER",
        password: str = "TAIL",
    ) -> None:
        self.files = dict(files)
        self.settings_dir = settings_dir
        self.user = user
        self.password = password
        self.err_missing = False
        self.errors = {}  # type: dict[str, bytes]  # ERR.TXT after uploading a file
        self.stor_errors = {}  # type: dict[str, list[Exception]]  # raised by STOR, in order
        self.err_txt = b""
        self.uploads = []  # type: list[tuple[str, bytes]]
        self.commands = []  # type: list[str]
        self.connections = 0

    def _err_path(self) -> str:
        return f"{self.settings_dir}/ERR.TXT" if self.settings_dir else "ERR.TXT"

    def listing(self, directory: str) -> list[str]:
        prefix = f"{directory}/" if directory else ""
        names = set()
        for path in self.files:
            if path.startswith(prefix):
                names.add(path[len(prefix) :].split("/")[0])
        return sorted(names)


class FakeFTPSession:
    """Stand-in for :class:`ftplib.FTP`, connected to a :class:`FakeRelay`."""

    def __init__(self, relay: FakeRelay) -> None:
        self.relay = relay
        self.cwd_path = ""

    def connect(self, host, port, timeout):  # noqa: ARG002
        self.relay.connections += 1
        return "220 SEL-710 FTP SERVER"

    def set_debuglevel(self, level):
        pass

    def login(self, user, passwd):
        if user != self.relay.user or passwd != self.relay.password:
            raise ftplib.error_perm("530 Login incorrect.")
        return "230 User logged in."

    def getwelcome(self):
        return "220 SEL-710 FTP SERVER"

    def _path(self, name: str) -> str:
        if name.startswith("/"):
            return name.strip("/")
        return f"{self.cwd_path}/{name}" if self.cwd_path else name

    def nlst(self, *args):
        directory = self._path(args[0]) if args else self.cwd_path
        return self.relay.listing(directory)

    def cwd(self, directory):
        path = self._path(directory)
        if path and path not in self.relay.listing(""):
            raise ftplib.error_perm(f"550 {directory}: No such directory")
        self.cwd_path = path
        self.relay.commands.append(f"CWD {directory}")
        return "250 OK"

    def pwd(self):
        return f"/{self.cwd_path}"

    def storlines(self, cmd, fp):
        name = cmd.split(" ", 1)[1]
        self.relay.commands.append(cmd)

        # Like ftplib: every line is sent with CRLF
        data = b""
        while True:
            buf = fp.readline(8193)
            if not buf:
                break
            if buf[-2:] != b"\r\n":
                if buf[-1:] in (b"\r", b"\n"):
                    buf = buf[:-1]
                buf = buf + b"\r\n"
            data += buf

        pending = self.relay.stor_errors.get(name)
        if pending:
            raise pending.pop(0)

        path = self._path(name)
        self.relay.uploads.append((path, data))
        self.relay.files[path] = data
        self.relay.err_txt = self.relay.errors.get(name, b"")
        return "226 Transfer complete."

    def retrbinary(self, cmd, callback):
        name = cmd.split(" ", 1)[1]
        self.relay.commands.append(cmd)
        path = self._path(name)

        if path == self.relay._err_path():
            if self.relay.err_missing:
                raise ftplib.error_perm("550 ERR.TXT: File not found")
            callback(self.relay.err_txt)
            return "226 Transfer complete."

        if path not in self.relay.files:
            raise ftplib.error_perm(f"550 {name}: File not found")
        callback(self.relay.files[path])
        return "226 Transfer complete."

    def quit(self):
        return "221 Goodbye."

    def close(self):
        pass


@pytest.fixture
def connect(mocker):
    """Make PEAT's FTP connections go to a fake relay."""

    def _connect(relay: FakeRelay) -> FakeRelay:
        mocker.patch("peat.protocols.ftp.ftplib.FTP", side_effect=lambda: FakeFTPSession(relay))
        return relay

    return _connect


def relay_710(**kwargs) -> FakeRelay:
    """A SEL-710 with the settings from the RDB, laid out like the 700 series (root only)."""
    cfg = (STREAMS_DIR / "Misc" / "Cfg.txt").read_bytes()
    cfg = SEL710_INFO + cfg[cfg.index(b"[CLASSES]") :]
    files = {"CFG.TXT": cfg, "CFG.XML": b"<xml/>", "ERR.TXT": b"", "SET_61850.CID": b"x"}
    for name in SEL710_FILES:
        settings = _stream_for(name).replace(b"\x1c", b"")
        files[name] = SEL710_INFO + settings[settings.index(b"[", 1) :]
    files["SET_ALL.TXT"] = b"read-only"
    return FakeRelay(files, **kwargs)


def relay_351s(**kwargs) -> FakeRelay:
    """A SEL-351S, with the settings in the SETTINGS directory."""
    files = {"CFG.TXT": SEL351S_CFG, "ERR.TXT": b"", "SETTINGS/ERR.TXT": b""}
    files["SETTINGS/SET_ALL.TXT"] = b"read-only"
    for name, data in SEL351S_FILES.items():
        files[f"SETTINGS/{name}"] = data
    return FakeRelay(files, settings_dir="SETTINGS", **kwargs)


def relay_421(**kwargs) -> FakeRelay:
    """A SEL-421, with the settings in the SETTINGS directory."""
    files = {"CFG.TXT": SEL421_CFG, "SETTINGS/ERR.TXT": b"", "SETTINGS/SET_ALL.TXT": b"read-only"}
    for name, data in SEL421_FILES.items():
        files[f"SETTINGS/{name}"] = data
    return FakeRelay(files, settings_dir="SETTINGS", **kwargs)


def make_dev(ip: str = "192.0.2.20", model: str = "", **sel_options):
    dev = datastore.get(ip, "ip")
    dev._module = SELRelay
    dev._is_verified = True
    dev._runtime_options["ftp"] = {"user": "FTPUSER", "pass": "TAIL", "pull_delay": 0}
    if sel_options:
        dev._runtime_options["sel"] = sel_options
    if model:
        dev.description.model = model
    return dev


def write_351s_dir(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in SEL351S_FILES.items():
        (directory / name).write_bytes(data)
    return directory


def stored_names(relay: FakeRelay) -> list[str]:
    return [PurePosixPath(path).name for path, _ in relay.uploads]


def push_file(dev, name: str):
    matches = [
        f
        for f in dev.files
        if f.name == name
        and f.extra.get("source") == "push"
        and "uploaded" not in str(f.local_path)
    ]
    assert len(matches) == 1, dev.files
    return matches[0]


def file_status(dev, name: str) -> dict:
    return next(f for f in dev.extra["push"]["files"] if f["name"] == name)


# ---------------------------------------------------------------------------
# Settings file conversions (relay_parse.py)
# ---------------------------------------------------------------------------


def test_normalize_settings_file():
    raw = (
        b"\xef\xbb\xbf[INFO]\nRELAYTYPE=SEL-710\r\n\r\n[1]\r\n"
        b'RID,"FEEDER \xb0 1"\x1c\r\n'
        b'TID,"STATION A"\x1c a comment\r\n'
        b'CTR,"1\x0020"\x1c\n'
        b"   \r\n\x1a"
    )
    expected = (
        b'[INFO]\r\nRELAYTYPE=SEL-710\r\n[1]\r\nRID,"FEEDER \xb0 1"\r\n'
        b'TID,"STATION A"\r\nCTR,"120"\r\n'
    )
    assert normalize_settings_file(raw) == expected
    assert normalize_settings_file(expected) == expected
    assert normalize_settings_file('[1]\nRID,"FEEDER 1"') == b'[1]\r\nRID,"FEEDER 1"\r\n'
    assert normalize_settings_file(b"\x1c\r\n\x00") == b""


def test_rdb_to_settings_files_sel710():
    files = rdb_to_settings_files(RDB_PATH.read_bytes())

    assert list(files) == SEL710_FILES
    for name, data in files.items():
        # Every line in the streams ends with 0x1C and an empty comment
        assert data == _stream_for(name).replace(b"\x1c", b""), name
        assert b"\x1c" not in data
        assert data.endswith(b"\r\n")
        assert data.startswith(b"[INFO]\r\nRELAYTYPE=SEL-710\r\n")

    assert rdb_to_settings_files(RDB_PATH.read_bytes(), RDB_RELAY) == files
    with pytest.raises(ParseError, match="No relay named 'Feeder 9'"):
        rdb_to_settings_files(RDB_PATH.read_bytes(), "Feeder 9")


def test_rdb_relay_settings_files_only_settings_streams():
    streams = {
        "Misc/Cfg.txt": (
            b'[INFO]\r\nRELAYTYPE=SEL-710\r\n[CLASSES]\r\nP5,"Port 5"\r\n1,"Group 1"\r\n'
        ),
        "Misc/Version": b"Saved on 30/08/2025 at 3:33:00 PM\r\n",
        "Misc/GL1.gle": b"\x00\x01\x02",
        "SET_ALL.TXT": b"[1]\r\n",
        "set_1.txt": b'[1]\r\nRID,"R"\x1c\r\n',
        "set_p5.txt": b'[P5]\r\nIPADDR,"192.0.2.1"\x1c\r\n',
        "set_9.txt": b"\x1c\r\n",  # Empty after cleaning
    }
    assert list(rdb_relay_settings_files(streams).items()) == [
        ("SET_P5.TXT", b'[P5]\r\nIPADDR,"192.0.2.1"\r\n'),
        ("SET_1.TXT", b'[1]\r\nRID,"R"\r\n'),
    ]


def test_settings_class_files_and_sorting():
    class_files = settings_class_files(
        [
            '"1","Group 1","SET_1.TXT","30C0490A"',
            'S1,"Group 1","\\SETTINGS\\SET_S1.TXT","0xd727d356"',
            'P5,"Port 5"',
            '"Saved on 2/16/2023 at 10:14:22 PM"',
        ]
    )
    assert class_files == {"1": "SET_1.TXT", "S1": "SET_S1.TXT", "P5": "SET_P5.TXT"}

    names = ["SET_10.TXT", "SET_P5.TXT", "SET_2.TXT", "SET_S1.TXT", "SET_1.TXT"]
    assert sort_settings_filenames(names, class_files) == [
        "SET_1.TXT",
        "SET_S1.TXT",
        "SET_P5.TXT",
        "SET_2.TXT",
        "SET_10.TXT",
    ]


def test_split_set_all_round_trip():
    # Without CFG.TXT, every file has the same [INFO] section as the streams
    streams = {name: data for name, data in _streams().items() if name.startswith("set_")}
    files = split_set_all(combine_settings_files(streams))

    assert sorted(files) == sorted(SEL710_FILES)
    for name, text in files.items():
        assert text.encode() == normalize_settings_file(_stream_for(name)), name


def test_split_set_all_sel710_set_all():
    # The SET_ALL.TXT in data_files has the [INFO] and [CLASSES] from Misc/Cfg.txt
    files = split_set_all((RELAY_DIR / "sel-710_SET_ALL.TXT").read_text())
    cfg_info = (STREAMS_DIR / "Misc" / "Cfg.txt").read_bytes().split(b"[CLASSES]")[0]

    assert list(files) == SEL710_FILES
    for name, text in files.items():
        stream = normalize_settings_file(_stream_for(name))
        body = stream[stream.index(b"\r\n[", 1) + 2 :]
        assert text.encode() == cfg_info + body, name


def test_split_set_all_400_series():
    # Layout of the SEL-421 settings (Table 5.10 in the SEL-421 manual), with the
    # [IOBOARDS] and [COMCARDS] sections after [INFO] (refer to SEL421_HEADER)
    text = (
        "[INFO]\r\n"
        "RELAYTYPE=SEL-421\r\n"
        "FID=SEL-421-5-R310-V0-Z016013-D20120223\r\n"
        "[CLASSES]\r\n"
        'S1,"Group 1","\\SETTINGS\\SET_S1.TXT","30C0490A"\r\n'
        'P5,"Port 5","\\SETTINGS\\SET_P5.TXT","E665D08E"\r\n'
        '"Saved on 2/16/2023 at 10:14:22 PM"\r\n'
        "[IOBOARDS]\r\n"
        ", , , 8, 8, 0, 0, 1\r\n"
        "[COMCARDS]\r\n"
        "[S1]\r\n"
        '"RID","Relay 1","","","","Relay Identifier"\r\n'
        "[P5]\r\n"
        '"TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"\r\n'
        "[STORAGE]\r\n"
        '"\\SWCFG.ZIP"\r\n'
    )
    header = (
        "[INFO]\r\nRELAYTYPE=SEL-421\r\nFID=SEL-421-5-R310-V0-Z016013-D20120223\r\n"
        "[IOBOARDS]\r\n, , , 8, 8, 0, 0, 1\r\n[COMCARDS]\r\n"
    )

    # The header sections are copied to every file, they aren't settings classes
    assert split_set_all(text) == {
        "SET_S1.TXT": header + '[S1]\r\n"RID","Relay 1","","","","Relay Identifier"\r\n',
        "SET_P5.TXT": (
            header + '[P5]\r\n"TPORT",23,"23,1025-65534",I,"","Telnet Port (23,1025-65534)"\r\n'
        ),
    }


def test_split_set_all_400_series_round_trip():
    # Each file keeps its own [IOBOARDS] and [COMCARDS] sections, which are
    # before its class in the combined settings
    files = dict(SEL421_FILES)
    files["SET_P5.TXT"] = files["SET_P5.TXT"].replace(b", , , 8, 8,", b", , , 4, 4,")

    combined = combine_settings_files(files)
    assert combined.count("[IOBOARDS]") == 3

    split = split_set_all(combined)
    assert {name: text.encode() for name, text in split.items()} == files
    assert not any("IOBOARDS" in name or "COMCARDS" in name for name in split)

    # The filenames are from the [CLASSES] in CFG.TXT, and every file has the header sections
    split = split_set_all(combine_settings_files({"CFG.TXT": SEL421_CFG, **SEL421_FILES}))
    assert list(split) == ["SET_S1.TXT", "SET_G1.TXT", "SET_P5.TXT"]
    for name, text in split.items():
        body = SEL421_FILES[name][SEL421_FILES[name].index(b"[IOBOARDS]") :]
        assert text.encode() == SEL421_CFG[: SEL421_CFG.index(b"[CLASSES]")] + body


def test_split_set_all_dnpb_round_trip():
    original = '[INFO]\r\nRELAYTYPE=0387\r\n[DNPB]\r\nDNPB,"52A 52B IN101"\r\n'
    combined = combine_settings_files({"SET_DNPB.TXT": original})
    assert 'BI_2,"52B"' in combined

    assert split_set_all(combined) == {"SET_DNPB.TXT": original}


def test_split_set_all_edge_cases(caplog):
    text = (
        "\ufeff[1]\n"
        'RID,"FEEDER \u0085 1"\x1c comment\n'
        "[MY CLASS]\n"
        'X,"1"\n'
        "[2]\n"
        'RID,"OLD"\n'
        "[2]\n"
        'RID,"NEW"\n'
    )
    files = split_set_all(text)

    # No [INFO], 0x85 isn't a line break, the last [2] is used, and [MY CLASS] isn't a class
    assert files == {
        "SET_1.TXT": '[1]\r\nRID,"FEEDER \u0085 1"\r\n',
        "SET_2.TXT": '[2]\r\nRID,"NEW"\r\n',
    }
    assert "No [INFO] section" in caplog.text
    assert "[MY CLASS]: not a valid settings class" in caplog.text
    assert "[2] is in the settings more than once" in caplog.text
    assert split_set_all("[INFO]\r\nRELAYTYPE=SEL-710\r\n[CLASSES]\r\n") == {}


# ---------------------------------------------------------------------------
# Helpers in sel_push.py
# ---------------------------------------------------------------------------


def test_placeholder_info():
    rdb_file = normalize_settings_file(_stream_for("SET_P1.TXT"))
    assert has_placeholder_info(rdb_file)
    assert not has_placeholder_info(SEL351S_FILES["SET_1.TXT"])
    assert not has_placeholder_info(b'[1]\r\nRID,"R"\r\n')

    replaced = replace_info_section(rdb_file, SEL710_INFO.decode().split("\r\n")[1:-1])
    assert replaced.startswith(SEL710_INFO + b"[P1]\r\nEPORT,")
    assert replaced.endswith(rdb_file[rdb_file.index(b"[P1]") :])
    assert not has_placeholder_info(replaced)

    # Added if there's no [INFO]
    assert replace_info_section(b'[1]\r\nRID,"R"\r\n', ["RELAYTYPE=SEL-710"]) == (
        b'[INFO]\r\nRELAYTYPE=SEL-710\r\n[1]\r\nRID,"R"\r\n'
    )


def test_order_for_upload():
    files = [
        PushFile(name=name, data=SEL351S_FILES[name], origin=name)
        for name in ["SET_P5.TXT", "SET_P1.TXT", "SET_1.TXT", "SET_L1.TXT", "SET_G.TXT"]
    ]
    assert [pf.name for pf in order_for_upload(files)] == [
        "SET_1.TXT",
        "SET_L1.TXT",
        "SET_G.TXT",
        "SET_P1.TXT",
        "SET_P5.TXT",
    ]


def _two_relays(ip_1: str = "192.0.2.20", ip_2: str = "192.0.2.21") -> dict:
    relays = {}
    for name, ip, rid in [("Feeder 1", ip_1, "FEEDER 1"), ("Feeder 2", ip_2, "FEEDER 2")]:
        streams = _streams()
        streams["set_P1.txt"] = streams["set_P1.txt"].replace(b"192.168.1.2", ip.encode())
        streams["set_1.txt"] = streams["set_1.txt"].replace(
            b'RID,"SEL-710"', f'RID,"{rid}"'.encode()
        )
        relays[name] = streams
    return relays


def test_select_rdb_relay():
    relays = _two_relays()

    assert select_rdb_relay(make_dev("192.0.2.21"), relays) == "Feeder 2"
    assert select_rdb_relay(make_dev("192.0.2.40"), relays, "feeder 1") == "Feeder 1"
    assert select_rdb_relay(make_dev("192.0.2.41"), {"Only": relays["Feeder 1"]}) == "Only"

    # The relay ID matches the device's name
    dev = make_dev("192.0.2.42")
    dev.name = "FEEDER 1"
    assert select_rdb_relay(dev, relays) == "Feeder 1"

    with pytest.raises(PushInputError, match="no relay named 'Feeder 3'"):
        select_rdb_relay(make_dev("192.0.2.43"), relays, "Feeder 3")

    with pytest.raises(PushInputError, match=r"no relay matches it.*sel\.push_rdb_relay"):
        select_rdb_relay(make_dev("192.0.2.44"), relays)

    # Template relays often have the same address
    with pytest.raises(PushInputError, match="several relays match it equally well"):
        select_rdb_relay(make_dev("192.0.2.20"), _two_relays("192.0.2.20", "192.0.2.20"))

    # Never a relay for a different model
    with pytest.raises(PushInputError, match="no relay matches it"):
        select_rdb_relay(make_dev("192.0.2.45", model="751"), _two_relays("192.0.2.45"))


# ---------------------------------------------------------------------------
# Preparing the push input
# ---------------------------------------------------------------------------


def test_prepare_push_rdb():
    plan = prepare_push(make_dev(), RDB_PATH)

    assert plan.input_type == "rdb"
    assert plan.rdb_relay == RDB_RELAY
    assert [pf.name for pf in plan.files] == SEL710_UPLOAD_ORDER
    assert plan.set_all == rdb_relay_to_set_all(read_rdb_streams(RDB_PATH.read_bytes())[RDB_RELAY])
    assert plan.files[0].origin == f"{RDB_PATH.name}: Relays/{RDB_RELAY}/set_1.txt"
    for pf in plan.files:
        assert pf.data == pf.upload_data == _stream_for(pf.name).replace(b"\x1c", b"")


def test_prepare_push_rdb_multiple_relays(mocker, caplog):
    mocker.patch.object(sel_push, "read_rdb_streams", return_value=_two_relays())

    plan = prepare_push(make_dev("192.0.2.21"), RDB_PATH)
    assert plan.rdb_relay == "Feeder 2"
    assert b'IPADDR,"192.0.2.21"' in next(pf.data for pf in plan.files if pf.name == "SET_P1.TXT")

    assert (
        prepare_push(make_dev("192.0.2.22"), RDB_PATH, rdb_relay="Feeder 1").rdb_relay
        == "Feeder 1"
    )
    assert prepare_push(make_dev("192.0.2.22"), RDB_PATH) is None
    assert "Set the 'sel.push_rdb_relay' option" in caplog.text


def test_prepare_push_rdb_without_relays(mocker, caplog):
    mocker.patch.object(sel_push, "read_rdb_streams", return_value={"": _streams()})
    assert prepare_push(make_dev(), RDB_PATH) is None
    assert "doesn't have the settings for relays in a 'Relays' storage" in caplog.text


def test_prepare_push_directory(tmp_path, caplog):
    # Settings files extracted from a RDB (lowercase), in a "SETTINGS" sub-directory
    source = tmp_path / "relay_files"
    (source / "SETTINGS").mkdir(parents=True)
    for path in STREAMS_DIR.glob("set_*.txt"):
        shutil.copy(path, source / "SETTINGS" / path.name)
    shutil.copy(STREAMS_DIR / "Misc" / "Cfg.txt", source / "cfg.txt")
    (source / "SET_ALL.TXT").write_bytes((RELAY_DIR / "sel-710_SET_ALL.TXT").read_bytes())
    (source / "notes.txt").write_text("not settings")

    plan = prepare_push(make_dev(), source)

    assert plan.input_type == "settings_files"
    assert [pf.name for pf in plan.files] == SEL710_UPLOAD_ORDER
    assert plan.files[0].origin == "SETTINGS/set_1.txt"
    assert "Ignoring SET_ALL.TXT" in caplog.text
    assert plan.set_all == combine_settings_files(
        {"CFG.TXT": (STREAMS_DIR / "Misc" / "Cfg.txt").read_bytes(), **_streams()}
    )


def test_prepare_push_directory_only_set_all(tmp_path):
    source = tmp_path / "settings"
    source.mkdir()
    shutil.copy(RELAY_DIR / "sel-710_SET_ALL.TXT", source / "set_all.txt")

    plan = prepare_push(make_dev(), source)
    assert plan.input_type == "set_all"
    assert sorted(pf.name for pf in plan.files) == sorted(SEL710_FILES)


def test_prepare_push_set_all_and_single_files(tmp_path):
    plan = prepare_push(make_dev(), RELAY_DIR / "sel-710_SET_ALL.TXT")
    assert plan.input_type == "set_all"
    assert [pf.name for pf in plan.files] == SEL710_UPLOAD_ORDER
    assert plan.files[0].origin == "sel-710_SET_ALL.TXT [1]"
    assert plan.set_all == (RELAY_DIR / "sel-710_SET_ALL.TXT").read_bytes().decode()

    single = tmp_path / "set_l1.txt"
    single.write_bytes(SEL351S_FILES["SET_L1.TXT"].replace(b"\r\n", b"\n"))
    plan = prepare_push(make_dev(), single)
    assert plan.input_type == "settings_files"
    assert [(pf.name, pf.data) for pf in plan.files] == [
        ("SET_L1.TXT", SEL351S_FILES["SET_L1.TXT"])
    ]

    # A single class in a file without the relay's name for it
    other = tmp_path / "relay7_group1.txt"
    other.write_bytes(SEL351S_FILES["SET_1.TXT"])
    assert [pf.name for pf in prepare_push(make_dev(), other).files] == ["SET_1.TXT"]


@pytest.mark.parametrize(
    ("filename", "data", "message"),
    [
        ("CFG.TXT", SEL351S_CFG, "CFG.TXT is read-only on relays"),
        ("err.txt", b"", "ERR.TXT is read-only on relays"),
        ("SET_1.TXT", SEL351S_FILES["SET_P1.TXT"], "has the settings for class [P1]"),
        ("SET_1.TXT", SEL351S_INFO, "doesn't have any settings sections"),
        ("notes.txt", b"[INFO]\r\n[CLASSES]\r\n", "doesn't have any settings sections"),
    ],
)
def test_prepare_push_refused(tmp_path, caplog, filename, data, message):
    path = tmp_path / filename
    path.write_bytes(data)
    dev = make_dev()
    assert prepare_push(dev, path) is None
    assert message in caplog.text

    # The reason is in the device results
    assert dev.extra["push"]["status"] == "failed"
    assert message in dev.extra["push"]["message"]
    assert dev.extra["push"]["input"] == path.as_posix()
    assert dev.extra["push"]["files"] == []


def test_prepare_push_refused_directory(tmp_path, caplog):
    source = tmp_path / "configs"
    source.mkdir()
    assert prepare_push(make_dev(), source) is None
    assert "couldn't find any settings files" in caplog.text

    (source / "SET_1.TXT").write_bytes(SEL351S_FILES["SET_1.TXT"])
    (source / "SETTINGS").mkdir()
    (source / "SETTINGS" / "set_1.txt").write_bytes(SEL351S_FILES["SET_1.TXT"])
    assert prepare_push(make_dev(), source) is None
    assert "are both SET_1.TXT" in caplog.text

    # Settings files for different models
    (source / "SETTINGS" / "set_1.txt").unlink()
    (source / "SET_P1.TXT").write_bytes(SEL710_INFO + b'[P1]\r\nIPADDR,"192.0.2.20"\r\n')
    dev = make_dev()
    assert not check_push_input(dev, prepare_push(dev, source))
    assert "the settings files are for different relay models" in caplog.text
    assert dev.extra["push"]["status"] == "failed"


def test_prepare_push_model_mismatch(caplog):
    # The device was identified as a SEL-751 when it was scanned
    dev = make_dev(model="751")
    assert not check_push_input(dev, prepare_push(dev, RDB_PATH))
    message = "the settings are for a SEL-710, but 192.0.2.20 is a SEL-751. Nothing was uploaded."
    assert message in caplog.text
    assert dev.extra["push"]["message"] == message

    dev = make_dev("192.0.2.21", model="710")
    assert check_push_input(dev, prepare_push(dev, RDB_PATH))


def test_prepare_push_ip_change_warning(caplog):
    dev = make_dev("192.0.2.99")
    assert check_push_input(dev, prepare_push(dev, RDB_PATH))
    assert "SET_P1.TXT sets the IP address (IPADDR) to 192.168.1.2" in caplog.text


def test_model_from_info():
    assert sel_push._model({"RELAYTYPE": "SEL-710"}) == "710"
    assert sel_push._model({"RELAYTYPE": "0351S", "FID": "SEL-351-R100"}) == "351S"
    assert sel_push._model({"RELAYTYPE": "SEL-487E-3"}) == "487E"
    assert sel_push._model({"FID": "SEL-710-RXXX-VX-Z008004-DXXXXXXXX"}) == "710"

    # RELAYTYPE=SEL in the SEL-421 manual's "Direct Networking Example", the model is in the FID
    assert sel_push._model({"RELAYTYPE": "SEL", "FID": "SEL-421-R120-V0-Z009005"}) == "421"
    assert sel_push._model({"RELAYTYPE": "SEL"}) == ""
    assert sel_push._model({}) == ""

    # A model without a number from a scan isn't compared
    dev = make_dev(model="SEL")
    assert sel_push._device_identifiers(dev)["model"] == set()


def test_prepare_push_400_series(tmp_path):
    expected = {name: normalize_settings_file(data) for name, data in SEL421_FILES.items()}
    upload_order = ["SET_S1.TXT", "SET_G1.TXT", "SET_P5.TXT"]

    # A directory, with CFG.TXT
    source = tmp_path / "relay_files"
    (source / "SETTINGS").mkdir(parents=True)
    (source / "CFG.TXT").write_bytes(SEL421_CFG)
    for name, data in SEL421_FILES.items():
        (source / "SETTINGS" / name.lower()).write_bytes(data)

    dev = make_dev("192.0.2.40", model="421")
    plan = prepare_push(dev, source)
    assert check_push_input(dev, plan)
    assert [(pf.name, pf.data) for pf in plan.files] == [(n, expected[n]) for n in upload_order]

    # A single file
    single = tmp_path / "SET_G1.TXT"
    single.write_bytes(SEL421_FILES["SET_G1.TXT"])
    plan = prepare_push(dev, single)
    assert check_push_input(dev, plan)
    assert [(pf.name, pf.data) for pf in plan.files] == [("SET_G1.TXT", expected["SET_G1.TXT"])]

    # A SET_ALL, split into the files with their header sections
    set_all = tmp_path / "SET_ALL.TXT"
    set_all.write_text(combine_settings_files({"CFG.TXT": SEL421_CFG, **SEL421_FILES}))
    plan = prepare_push(dev, set_all)
    assert check_push_input(dev, plan)
    assert [pf.name for pf in plan.files] == upload_order
    for pf in plan.files:
        assert pf.data.endswith(expected[pf.name][expected[pf.name].index(b"[IOBOARDS]") :])


# ---------------------------------------------------------------------------
# Pushing to a relay
# ---------------------------------------------------------------------------


def test_push_rdb_to_700_series(connect, env):
    relay = connect(relay_710())
    dev = make_dev()

    assert SELRelay.push(dev, RDB_PATH, "config")

    # P* last, with the Ethernet port at the end, and ERR.TXT read after each file
    assert stored_names(relay) == SEL710_UPLOAD_ORDER
    assert [c for c in relay.commands if c.startswith(("STOR", "RETR ERR"))] == [
        cmd for name in SEL710_UPLOAD_ORDER for cmd in [f"STOR {name}", "RETR ERR.TXT"]
    ]
    assert relay.commands[0] == "RETR CFG.TXT"
    assert not any(c.startswith("CWD") for c in relay.commands)
    assert relay.connections == 1

    out_dir = env / "devices" / "192.0.2.20"
    assert (out_dir / "push_SET_ALL.txt").read_bytes() == rdb_relay_to_set_all(
        read_rdb_streams(RDB_PATH.read_bytes())[RDB_RELAY]
    ).encode()
    assert (out_dir / "push_files" / "from_relay" / "CFG.TXT").read_bytes() == relay.files[
        "CFG.TXT"
    ]

    for path, uploaded in relay.uploads:
        prepared = _stream_for(path).replace(b"\x1c", b"")
        # The placeholder [INFO] from the RDB was replaced with the relay's
        assert uploaded == SEL710_INFO + prepared[prepared.index(b"[", 1) :]
        assert (out_dir / "push_files" / path).read_bytes() == prepared
        assert (out_dir / "push_files" / "uploaded" / path).read_bytes() == uploaded

        uploaded_file = next(
            f for f in dev.files if f.local_path == (out_dir / "push_files" / "uploaded" / path)
        )
        assert uploaded_file.path == PurePosixPath(f"/{path}")
        assert uploaded_file.hash.dict(exclude_none=True) == _hashes(uploaded)
        assert uploaded_file.extra["transport"] == "ftp"
        assert uploaded_file.extra["push"]["status"] == "accepted"

        prepared_file = push_file(dev, path)
        assert prepared_file.hash.dict(exclude_none=True) == _hashes(prepared)
        assert prepared_file.extra["push"] == {"status": "accepted", "message": "", "attempts": 1}
        assert set(_hashes(prepared).values()) <= dev.related.hash

    assert dev.extra["push"]["status"] == "success"
    assert dev.extra["push"]["input_type"] == "rdb"
    assert dev.extra["push"]["rdb_relay"] == RDB_RELAY
    assert [f["status"] for f in dev.extra["push"]["files"]] == ["accepted"] * 15

    # SET_ALL.TXT, CFG.TXT and ERR.TXT are read-only
    assert relay.files["SET_ALL.TXT"] == b"read-only"
    assert not set(stored_names(relay)) & {"SET_ALL.TXT", "CFG.TXT", "ERR.TXT"}


def test_push_directory_to_351s(connect, env, tmp_path):
    relay = connect(relay_351s())
    dev = make_dev("192.0.2.30", model="351S")
    source = write_351s_dir(tmp_path / "configs")
    (source / "SET_ALL.TXT").write_bytes(b"[1]\r\n")
    (source / "CFG.TXT").write_bytes(SEL351S_CFG)

    assert SELRelay.push(dev, source, "config")

    # The settings are in the SETTINGS directory, Port 5 (Ethernet) is last
    assert relay.commands[:2] == ["RETR CFG.TXT", "CWD /SETTINGS"]
    assert [path for path, _ in relay.uploads] == [
        "SETTINGS/SET_1.TXT",
        "SETTINGS/SET_G.TXT",
        "SETTINGS/SET_L1.TXT",
        "SETTINGS/SET_P1.TXT",
        "SETTINGS/SET_P5.TXT",
    ]
    # A real [INFO] isn't replaced
    for path, data in relay.uploads:
        assert data == SEL351S_FILES[PurePosixPath(path).name]
        assert push_file(dev, PurePosixPath(path).name).path == PurePosixPath(f"/{path}")

    assert not (env / "devices" / "192.0.2.30" / "push_files" / "uploaded").exists()
    assert relay.files["SETTINGS/SET_ALL.TXT"] == b"read-only"
    assert dev.extra["push"]["status"] == "success"


def test_push_rejected_stops_push(connect, env, caplog):
    relay = connect(relay_710())
    # SET_2.TXT is before the Logic settings, so it isn't retried
    relay.errors["SET_2.TXT"] = b"PHROT := XYZ  Invalid setting\r\n"
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")

    assert stored_names(relay) == ["SET_1.TXT", "SET_2.TXT"]
    assert file_status(dev, "SET_1.TXT")["status"] == "accepted"
    assert file_status(dev, "SET_2.TXT") == {
        "name": "SET_2.TXT",
        "status": "rejected",
        "message": "PHROT := XYZ  Invalid setting",
        "attempts": 1,
        "origin": f"{RDB_PATH.name}: Relays/{RDB_RELAY}/set_2.txt",
    }
    assert {file_status(dev, name)["status"] for name in SEL710_UPLOAD_ORDER[2:]} == {"prepared"}
    assert dev.extra["push"]["status"] == "failed"
    assert "The relay rejected SET_2.TXT" in dev.extra["push"]["message"]
    assert push_file(dev, "SET_2.TXT").extra["push"]["status"] == "rejected"

    err_path = env / "devices" / "192.0.2.20" / "push_files" / "from_relay" / "ERR_SET_2.TXT"
    assert err_path.read_bytes() == relay.errors["SET_2.TXT"]
    err_file = next(f for f in dev.files if f.local_path == err_path)
    assert err_file.name == "ERR.TXT"
    assert err_file.path == PurePosixPath("/ERR.TXT")
    assert err_file.hash.dict(exclude_none=True) == _hashes(relay.errors["SET_2.TXT"])
    assert "Errors in ERR.TXT: PHROT := XYZ" in caplog.text


def test_push_700_series_uploads_rejected_file_again_after_wait(connect, clock, mocker):
    relay = connect(relay_710())
    relay.errors["SET_G.TXT"] = b"Settings change not allowed\r\n"
    dev = make_dev()

    def _accept_after_wait(seconds):
        clock.sleep(seconds)
        if seconds > sel_push.RETRY_INTERVAL:
            relay.errors.pop("SET_G.TXT", None)

    mocker.patch.object(sel_push, "sleep", _accept_after_wait)
    assert SELRelay.push(dev, RDB_PATH, "config")

    # SET_L3.TXT was accepted just before SET_G.TXT. SET_G.TXT was rejected 2 seconds
    # later (after the delay before reading ERR.TXT), and it's uploaded again once,
    # when the two minutes are up (118 seconds later).
    wait = sel_push.SEL700_SETTINGS_WAIT - sel_push.UPLOAD_DELAY
    assert clock.sleeps.count(wait) == 1
    assert sel_push.RETRY_INTERVAL not in clock.sleeps
    assert file_status(dev, "SET_G.TXT") == {
        "name": "SET_G.TXT",
        "status": "accepted",
        "message": "",
        "attempts": 2,
        "origin": f"{RDB_PATH.name}: Relays/{RDB_RELAY}/set_G.txt",
    }
    assert stored_names(relay).count("SET_G.TXT") == 2


def test_push_700_series_waits_after_logic_change(connect, clock):
    relay = connect(relay_710())
    # The relay isn't ready for another settings change after the Logic 1 settings
    relay.stor_errors["SET_L2.TXT"] = [
        ftplib.error_temp("450 Settings change in progress"),
        ftplib.error_temp("450 Settings change in progress"),
    ]
    dev = make_dev()

    assert SELRelay.push(dev, RDB_PATH, "config")

    assert stored_names(relay) == SEL710_UPLOAD_ORDER
    assert file_status(dev, "SET_L2.TXT")["attempts"] == 3
    assert file_status(dev, "SET_L2.TXT")["status"] == "accepted"
    assert clock.sleeps.count(sel_push.RETRY_INTERVAL) == 2


def test_push_700_series_refused_upload_gives_up(connect, clock):
    relay = connect(relay_710())
    relay.stor_errors["SET_L2.TXT"] = [ftplib.error_temp("450 Settings change in progress")] * 20
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")

    # Retried every 10 seconds until two minutes after SET_L1.TXT was accepted.
    # The STOR fails right away, so the attempts are at 0, 10, ..., 120 seconds.
    assert file_status(dev, "SET_L2.TXT")["attempts"] == 13
    assert clock.sleeps.count(sel_push.RETRY_INTERVAL) == 12
    assert "SET_L2.TXT" not in stored_names(relay)
    assert stored_names(relay)[-1] == "SET_L1.TXT"
    assert file_status(dev, "SET_L2.TXT")["status"] == "failed"


def test_push_700_series_rejected_file_uploaded_again_once(connect, clock):
    relay = connect(relay_710())
    relay.errors["SET_L2.TXT"] = b"Settings change not allowed\r\n"
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")

    # A real error in the settings isn't written over and over: the file is
    # uploaded again once, when the two minutes after SET_L1.TXT are up
    assert file_status(dev, "SET_L2.TXT")["attempts"] == 2
    assert sel_push.RETRY_INTERVAL not in clock.sleeps
    assert clock.sleeps.count(sel_push.SEL700_SETTINGS_WAIT - sel_push.UPLOAD_DELAY) == 1
    assert stored_names(relay)[-2:] == ["SET_L2.TXT", "SET_L2.TXT"]
    assert "SET_L3.TXT" not in stored_names(relay)
    assert file_status(dev, "SET_L2.TXT")["status"] == "rejected"


def test_push_unknown_model_no_wait(connect, clock):
    relay = relay_710()
    del relay.files["CFG.TXT"]
    relay.errors["SET_L2.TXT"] = b"Settings change not allowed\r\n"
    connect(relay)
    dev = make_dev()  # Not scanned, so the model isn't known

    assert not SELRelay.push(dev, RDB_PATH, "config")

    # Without the model, there's no wait, and the push stops at the first rejected file
    assert file_status(dev, "SET_L2.TXT")["attempts"] == 1
    assert set(clock.sleeps) == {sel_push.UPLOAD_DELAY}
    assert stored_names(relay)[-1] == "SET_L2.TXT"


def test_push_300_series_no_wait(connect, clock, tmp_path):
    relay = connect(relay_351s())
    relay.stor_errors["SET_P1.TXT"] = [ftplib.error_perm("550 Permission denied")]
    dev = make_dev("192.0.2.30", model="351S")

    assert not SELRelay.push(dev, write_351s_dir(tmp_path / "configs"), "config")

    # No retries after the Logic settings, since it's not a 700 series relay
    assert file_status(dev, "SET_P1.TXT") == {
        "name": "SET_P1.TXT",
        "status": "failed",
        "message": "The relay refused the upload: 550 Permission denied",
        "attempts": 1,
        "origin": "SET_P1.TXT",
    }
    assert sel_push.RETRY_INTERVAL not in clock.sleeps
    assert stored_names(relay) == ["SET_1.TXT", "SET_G.TXT", "SET_L1.TXT"]


def test_push_directory_to_421(connect, tmp_path):
    relay = connect(relay_421())
    dev = make_dev("192.0.2.40", model="421", push_unlisted_files=True)
    source = tmp_path / "configs"
    source.mkdir()
    for name, data in SEL421_FILES.items():
        (source / name).write_bytes(data)

    assert SELRelay.push(dev, source, "config")

    # The settings files are uploaded with their [IOBOARDS] and [COMCARDS] sections,
    # which aren't uploaded as files, even if unlisted files are allowed. There's no
    # CFG.TXT in the directory, so the files are in natural order, with the port last.
    assert relay.commands[:2] == ["RETR CFG.TXT", "CWD /SETTINGS"]
    assert relay.uploads == [
        (f"SETTINGS/{name}", SEL421_FILES[name])
        for name in ["SET_G1.TXT", "SET_S1.TXT", "SET_P5.TXT"]
    ]
    assert relay.commands.count("RETR ERR.TXT") == 3
    assert dev.extra["push"]["status"] == "success"
    assert {f["status"] for f in dev.extra["push"]["files"]} == {"accepted"}


def test_push_refused_before_connecting_keeps_files(connect, env):
    relay = connect(relay_710())
    # The device was identified as a SEL-751 when it was scanned
    dev = make_dev(model="751")

    assert not SELRelay.push(dev, RDB_PATH, "config")

    # Nothing was sent, but the settings and the reason are in the device results
    assert relay.connections == 0
    out_dir = env / "devices" / "192.0.2.20"
    assert (out_dir / "push_SET_ALL.txt").is_file()
    for name in SEL710_FILES:
        assert (out_dir / "push_files" / name).is_file()
        assert push_file(dev, name).extra["push"]["status"] == "prepared"
    assert dev.extra["push"]["status"] == "failed"
    assert (
        "the settings are for a SEL-710, but 192.0.2.20 is a SEL-751"
        in (dev.extra["push"]["message"])
    )
    assert any(f.name == "push_SET_ALL.txt" for f in dev.files)


def test_push_login_failure_keeps_files(connect, env):
    relay = connect(relay_710(password="NOT TAIL"))
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")

    assert not relay.uploads
    out_dir = env / "devices" / "192.0.2.20"
    assert (out_dir / "push_SET_ALL.txt").is_file()
    for name in SEL710_FILES:
        assert (out_dir / "push_files" / name).read_bytes() == _stream_for(name).replace(
            b"\x1c", b""
        )
        assert push_file(dev, name).extra["push"]["status"] == "prepared"
    assert dev.extra["push"]["status"] == "failed"
    assert "Nothing was uploaded" in dev.extra["push"]["message"]

    set_all_file = next(f for f in dev.files if f.name == "push_SET_ALL.txt")
    assert set_all_file.hash.dict(exclude_none=True) == _hashes(
        (out_dir / "push_SET_ALL.txt").read_bytes()
    )
    assert set_all_file.extra["derived_from"] == [RDB_PATH.name]


def test_push_files_recorded_without_device_dir(connect, mocker):
    mocker.patch.dict(config["CONFIG"], {"DEVICE_DIR": None})
    connect(relay_710(password="NOT TAIL"))
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")

    for name in SEL710_FILES:
        prepared = push_file(dev, name)
        assert prepared.local_path is None
        assert prepared.hash.dict(exclude_none=True) == _hashes(
            _stream_for(name).replace(b"\x1c", b"")
        )


def test_push_files_not_on_relay(connect):
    relay = relay_710()
    del relay.files["SET_M.TXT"]
    relay.files["CFG.TXT"] = relay.files["CFG.TXT"].replace(b'M,"Modbus User Map"\r\n', b"")
    connect(relay)

    dev = make_dev()
    assert not SELRelay.push(dev, RDB_PATH, "config")
    assert not relay.uploads
    assert "1 of the settings files aren't on the relay: SET_M.TXT" in dev.extra["push"]["message"]

    # A file that's only listed in CFG.TXT is on the relay
    relay.files["CFG.TXT"] = relay_710().files["CFG.TXT"]
    assert SELRelay.push(make_dev("192.0.2.21"), RDB_PATH, "config")


def test_push_files_not_on_relay_allowed(connect):
    relay = relay_710()
    del relay.files["SET_M.TXT"]
    relay.files["CFG.TXT"] = relay.files["CFG.TXT"].replace(b'M,"Modbus User Map"\r\n', b"")
    connect(relay)

    assert SELRelay.push(make_dev(push_unlisted_files=True), RDB_PATH, "config")
    assert "SET_M.TXT" in stored_names(relay)


def test_push_relay_model_mismatch(connect):
    relay = relay_710()
    relay.files["CFG.TXT"] = relay.files["CFG.TXT"].replace(
        b"RELAYTYPE=SEL-710", b"RELAYTYPE=SEL-751"
    )
    connect(relay)
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")
    assert not relay.uploads
    assert "SET_1.TXT is for a SEL-710, but the relay is a SEL-751" in dev.extra["push"]["message"]


def test_push_settings_version_mismatch(connect, caplog):
    relay = relay_710()
    relay.files["CFG.TXT"] = relay.files["CFG.TXT"].replace(b"Z008004", b"Z007004")
    connect(relay)

    assert SELRelay.push(make_dev(), RDB_PATH, "config")

    # One warning for all of the files
    names = ", ".join(SEL710_UPLOAD_ORDER)
    assert f"{names} have settings version Z008004, but the relay's firmware has " in caplog.text
    assert "has settings version Z007004 (the Z-number in the FID)" in caplog.text
    assert caplog.text.count("have settings version Z008004") == 1


def test_push_without_err_txt(connect, caplog):
    relay = connect(relay_710())
    relay.err_missing = True
    dev = make_dev()

    assert SELRelay.push(dev, RDB_PATH, "config")

    assert stored_names(relay) == SEL710_UPLOAD_ORDER
    assert {f["status"] for f in dev.extra["push"]["files"]} == {"unverified"}
    assert dev.extra["push"]["status"] == "success"
    assert "15 files were uploaded but not checked" in dev.extra["push"]["message"]
    assert "ERR.TXT couldn't be read" in caplog.text


def test_push_without_cfg_txt(connect, caplog):
    relay = relay_710()
    del relay.files["CFG.TXT"]
    connect(relay)
    dev = make_dev()

    # Without the relay's [INFO], the files are uploaded as they are in the RDB
    assert SELRelay.push(dev, RDB_PATH, "config")
    assert "Failed to read CFG.TXT" in caplog.text
    assert relay.uploads[0][1] == _stream_for("SET_1.TXT").replace(b"\x1c", b"")


def test_push_connection_ends_after_port_settings(connect):
    relay = connect(relay_710())
    # The relay applies the new Port 1 (Ethernet) settings and the connection ends
    relay.stor_errors["SET_P1.TXT"] = [ConnectionResetError("Connection reset by peer")]
    dev = make_dev()

    assert SELRelay.push(dev, RDB_PATH, "config")
    assert file_status(dev, "SET_P1.TXT")["status"] == "unverified"
    assert (
        "expected if they're the settings for the port"
        in file_status(dev, "SET_P1.TXT")["message"]
    )
    assert push_file(dev, "SET_P1.TXT").extra["push"]["status"] == "unverified"


def test_push_connection_lost(connect):
    relay = connect(relay_710())
    relay.stor_errors["SET_2.TXT"] = [ConnectionResetError("Connection reset by peer")]
    dev = make_dev()

    assert not SELRelay.push(dev, RDB_PATH, "config")
    assert stored_names(relay) == ["SET_1.TXT"]
    assert file_status(dev, "SET_2.TXT")["status"] == "failed"
    assert file_status(dev, "SET_3.TXT")["status"] == "prepared"


def test_push_does_not_restart_by_default(connect, mocker):
    restart = mocker.patch.object(SELRelay, "restart_relay_telnet", return_value=True)
    connect(relay_710())

    assert SELRelay.push(make_dev(), RDB_PATH, "config")
    restart.assert_not_called()


def test_push_unsupported_inputs():
    dev = make_dev()
    assert not SELRelay.push(dev, RDB_PATH, "firmware")
    assert not SELRelay._push(dev, RDB_PATH.read_bytes(), "config")
    assert "push" not in dev.extra


def test_pushed_bytes_are_crlf(connect, tmp_path):
    # Files with LF line endings (e.g. edited on Linux) are uploaded with CRLF
    relay = connect(relay_351s())
    source = tmp_path / "SET_1.TXT"
    source.write_bytes(SEL351S_FILES["SET_1.TXT"].replace(b"\r\n", b"\n"))
    dev = make_dev("192.0.2.30")

    assert SELRelay.push(dev, source, "config")
    assert relay.uploads == [("SETTINGS/SET_1.TXT", SEL351S_FILES["SET_1.TXT"])]
    assert push_file(dev, "SET_1.TXT").hash.dict(exclude_none=True) == _hashes(
        SEL351S_FILES["SET_1.TXT"]
    )


def test_sel710_streams_fixture():
    # Cleaning the streams only removes the 0x1C at the end of each settings line
    for name in SEL710_FILES:
        stream = _stream_for(name)
        assert stream.count(b"\x1c") == stream.count(b"\x1c\r\n") > 0
        assert normalize_settings_file(stream) == stream.replace(b"\x1c", b"")
