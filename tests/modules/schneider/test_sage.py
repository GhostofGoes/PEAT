"""
Tests for the Sage RTU module with synthetic inputs.

The command outputs follow the formats documented in the code comments of
``peat/modules/schneider/sage/`` and the VxWorks shell reference (``checkStack``,
``ti``). The XML files are synthetic: there are no public Sage configuration
samples, so attribute names are representative, not captured from a device.
"""

import io
import tarfile
from datetime import UTC, datetime
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest

from peat import DeviceData, Sage, config, datastore
from peat.data.baseline import compare_device, split_path
from peat.modules.schneider.sage import sage_commands, sage_parse
from peat.modules.schneider.sage.sage_telnet import SageTelnet

CHECK_STACK = """\
NAME         ENTRY        TID        SIZE   CUR  HIGH  MARGIN
------------ ------------ -------- ----- ----- ----- ------
tExcTask     excTask      0x1c3fa40   7984   224   696   7288
tShell0      shellTask    0x1d02b10  20000  1240  4096  OVERFLOW
INTERRUPT                             5000     0   512   4488
"""

TI_EXC = """\
  NAME         ENTRY       TID    PRI   STATUS      PC       SP     ERRNO  DELAY
---------- ------------ -------- --- ---------- -------- -------- ------- -----
tExcTask   excTask      1c3fa40    0 PEND+T       2a3b4c  1c3f900       0     0
stack: base 0x1c3fa40  end 0x1c3db00  size 7984  high 696  margin 7288
task entry : excTask
process    : kernel
options    : 0x1005
"""


@pytest.fixture
def out_config(mocker, tmp_path):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _tasks() -> dict:
    tasks = sage_commands.parse_check_stack_response(CHECK_STACK)
    assert sage_commands.parse_ti_response(TI_EXC, tasks["0x1c3fa40"])
    return tasks


def test_task_state():
    assert sage_commands.task_state("PEND+T") == "pended"
    assert sage_commands.task_state("READY") == "ready"
    assert sage_commands.task_state("DELAY") == "delayed"
    assert sage_commands.task_state("SUSPEND") == "suspended"
    assert sage_commands.task_state("WEIRD") == "weird"
    assert sage_commands.task_state("") == ""


def test_tasks_to_processes():
    procs = {p.name: p for p in sage_commands.tasks_to_processes(_tasks())}
    assert set(procs) == {"tExcTask", "tShell0"}

    exc = procs["tExcTask"]
    assert exc.type == "task"
    assert exc.pid == 0x1C3FA40
    assert exc.priority == 0
    assert exc.state == "pended"
    assert exc.extra["task_id"] == "0x1c3fa40"
    assert exc.extra["state_code"] == "PEND+T"
    assert exc.extra["entry"] == "excTask"
    assert exc.extra["rtp"] == "kernel"
    assert exc.extra["options"] == "0x1005"
    assert exc.extra["stack_size"] == 7984
    assert exc.extra["stack_high"] == 696
    assert exc.extra["stack_margin"] == 7288

    shell = procs["tShell0"]
    assert shell.priority is None
    assert shell.state == ""
    assert shell.extra["stack_margin"] == "OVERFLOW"


def test_process_tasks_store_and_related():
    dev = DeviceData()
    sage_commands.process_tasks(_tasks(), dev)
    sage_commands.process_tasks(_tasks(), dev)  # second pull merges
    assert len(dev.processes) == 2
    assert {"tExcTask", "tShell0"} <= dev.related.process


def test_convert_memory_reads_continues_after_bad_task():
    tasks = {
        "0x1": {"d_response": "0x00001000  zzzzzzzzzzzzzzzz  *................*"},
        "0x2": {"d_response": '0x00002000  0011223344556677  *.."3DUfw*'},
    }
    sage_commands.convert_memory_reads_to_hex_strings(tasks)
    assert tasks["0x1"]["memory_hex"] == ""
    assert tasks["0x2"]["memory_hex"] == "0011223344556677"
    assert tasks["0x2"]["memory_bytes"] == bytes.fromhex("0011223344556677")


def test_software_versions():
    assert sage_commands.parse_openssl_version("OpenSSL 1.0.1k 8 Jan 2015\n") == {
        "name": "OpenSSL",
        "version": "1.0.1k",
        "build_date": "8 Jan 2015",
    }
    assert sage_commands.parse_openssl_version("Cmd: 'ipcrypto_ver' not found.") == {}

    ipversion = (
        "@(#) IPCOM $Name: VXWORKS_ITER32_2015032510 $ - INTERPEAK_COPYRIGHT_STRING\n"
        "@(#) IPNET $Name: VXWORKS_ITER32_2015032510 $ - INTERPEAK_COPYRIGHT_STRING\n"
        "@(#) IPCOM $Name: VXWORKS_ITER32_2015032510 $ - INTERPEAK_COPYRIGHT_STRING\n"
    )
    components = sage_commands.parse_ipversion(ipversion)
    assert components == [
        {"name": "IPCOM", "version": "VXWORKS_ITER32_2015032510"},
        {"name": "IPNET", "version": "VXWORKS_ITER32_2015032510"},
    ]

    dev = DeviceData()
    sage_commands.process_software_versions(
        dev, openssl=sage_commands.parse_openssl_version("OpenSSL 1.0.1k 8 Jan 2015")
    )
    sage_commands.process_software_versions(dev, components=components)
    pkgs = {p.name: p for p in dev.software}
    assert pkgs["OpenSSL"].version == "1.0.1k"
    assert pkgs["OpenSSL"].category == "library"
    assert pkgs["OpenSSL"].type == ""
    assert pkgs["IPCOM"].category == "os_component"

    isagraf = sage_parse.isagraf_package({"version": "5.21", "note": "Soft Logic Controller"})
    assert isagraf.name == "ISaGRAF"
    assert isagraf.category == "plc_runtime"
    assert sage_parse.isagraf_package({}) is None


def test_rtusetup_placeholders():
    xml = b"""<RTU_SETUP><CPU>
      <RTU><NAME>ChangeMe</NAME><SERIALNUM>12345</SERIALNUM><TYPE>3030M</TYPE>
        <VXWORKS><VXVERSION>changeme</VXVERSION><VXCREATED>Jan 21 2011</VXCREATED></VXWORKS>
      </RTU>
      <CONFIG><NAME>cfg-1</NAME><REVISION>ChangeMe</REVISION></CONFIG>
    </CPU></RTU_SETUP>"""
    info = {}
    sage_parse.parse_rtu_setup(io.BytesIO(xml), info)
    rtu = info["rtusetup_info"]
    assert rtu["placeholders"] == ["CONFIG/REVISION", "RTU/NAME", "RTU/VXWORKS/VXVERSION"]
    assert "name" not in rtu
    assert rtu["serial_number"] == "12345"
    assert rtu["config_version"] == "cfg-1"


def test_access_xml_passwords_not_exported():
    xml = b"""<ACCESS>
      <USER ID="Admin" SESTIMEOUT="30"><DESC>Administrator</DESC><PASSWORD>secret</PASSWORD>
        <ACCESS FTP="Y" TELNET="N"/></USER>
      <USER ID="viewer"><ACCESS FTP="N"/></USER>
    </ACCESS>"""
    info = {}
    sage_parse.parse_access_xml(io.BytesIO(xml), info)
    redacted = sage_parse.redact_access_info(info["access_info"])
    assert redacted["users"][0]["password_set"] is True
    assert "password" not in redacted["users"][0]
    assert "password_set" not in redacted["users"][1]
    assert info["access_info"]["users"][0]["password"] == "secret"  # input unchanged
    assert "secret" not in str(redacted)


def test_parse_never_writes_secrets(out_config):
    """ACCESS.XML and ethernet.xml passwords never reach any output file."""
    xml_dir = out_config / "sage_in" / "ata0a" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "ACCESS.XML").write_bytes(
        b'<ACCESS><USER ID="Admin" SESTIMEOUT="10"><DESC>Administrator</DESC>'
        b'<PASSWORD>SuperSecret1!</PASSWORD><ACCESS FTP="Y" TELNET="N"/></USER></ACCESS>'
    )
    dev = Sage.parse(xml_dir / "ACCESS.XML")
    assert dev.extra["access_info"]["users"][0]["password_set"] is True
    for path in (out_config / "devices").rglob("*.json"):
        assert "SuperSecret1!" not in path.read_text(), path
    for path in (out_config / "temp").rglob("*"):
        if path.is_file():
            assert "SuperSecret1!" not in path.read_text(errors="ignore"), path


def _write_tar(tar_path, members: dict[str, bytes], mtime: int = 1_700_000_000) -> None:
    with tarfile.open(tar_path, "w:gz", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(data))


def test_parse_archive_never_writes_keys_or_bootline_password(out_config):
    """The private keys and the VxWorks boot line password never reach any output."""
    tar_path = out_config / "in" / "config.tar.gz"
    tar_path.parent.mkdir()
    server_key = b"-----BEGIN PRIVATE KEY-----\nServerKeyMaterial\n-----END PRIVATE KEY-----\n"
    ike_key = b"-----BEGIN RSA PRIVATE KEY-----\nIkeKeyMaterial\n-----END RSA PRIVATE KEY-----\n"
    _write_tar(
        tar_path,
        {
            "bootline.xml": b'<BOOT><BOOTLINE h="192.0.2.2" e="192.0.2.50:ffffff00" '
            b'g="192.0.2.1" u="target" pw="BootPw123" tn="sage" f="0x8"/></BOOT>',
            "ssl/server.key": server_key,
            "ike/priv0.key": ike_key,
        },
    )
    dev = Sage.parse(tar_path)

    bootline = dev.extra["bootline_from_xml"]
    assert "pw" not in bootline
    assert bootline["password_set"] is True
    assert bootline["u"] == "target"
    assert "BootPw123" not in str(dev.export())

    secrets = ("BootPw123", "ServerKeyMaterial", "IkeKeyMaterial")
    written = list((out_config / "devices").rglob("*.json"))
    written += [p for p in (out_config / "temp").rglob("*") if p.is_file()]
    assert any(p.name == "parsed-config.json" for p in written)
    for path in written:
        text = path.read_text(errors="ignore")
        for secret in secrets:
            assert secret not in text, (secret, path)
    parsed = next(p for p in written if p.name == "parsed-config.json").read_text()
    assert '"server_private_key_present": true' in parsed
    assert '"privkey_present": true' in parsed


def test_parse_archive_never_writes_script_or_ike_secrets(out_config):
    """The passwords and keys in the startup scripts and ike.cfg never reach any output."""
    tar_path = out_config / "in" / "scripts.tar.gz"
    tar_path.parent.mkdir()
    _write_tar(
        tar_path,
        {
            "scripts/vxworks_start.scp": b'cd "/ata0a"\r\nloginUserAdd "Admin","VxHashCanary"\r\n'
            b'iam "target", "VxIamCanary"\r\nhostAdd "rtu2", "192.0.2.20"\r\n',
            "scripts/startup.scp": b'remCurIdSet("ftpuser", "StRemCanary");\n'
            b"bootParams pw=StBootCanary tn=sage\n",
            "ike/ike.cfg": b"# IKE configuration\nauthentication_method pre_shared_key;\n"
            b'pre_shared_key "IkePskCanary";\nsecret = IkeSecretCanary\nlifetime 3600\n',
        },
    )
    dev = Sage.parse(tar_path)

    script = dev.extra["vxworks_startup_script"]
    assert 'loginUserAdd "Admin", <redacted>' in script
    assert 'iam "target", <redacted>' in script
    assert 'hostAdd "rtu2", "192.0.2.20"' in script  # the rest of the script is kept

    secrets = (
        "VxHashCanary",
        "VxIamCanary",
        "StRemCanary",
        "StBootCanary",
        "IkePskCanary",
        "IkeSecretCanary",
    )
    exported = str(dev.export()) + str(dev.elastic())
    written = list((out_config / "devices").rglob("*.json"))
    written += [p for p in (out_config / "temp").rglob("*") if p.is_file()]
    parsed = next(p for p in written if p.name == "parsed-config.json")
    parsed = parsed.read_text(encoding="utf-8")
    assert "authentication_method pre_shared_key;" in parsed
    assert "lifetime 3600" in parsed
    assert 'remCurIdSet(\\"ftpuser\\", <redacted>);' in parsed
    for secret in secrets:
        assert secret not in exported, secret
        for path in written:
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert secret not in text, (secret, path)


def test_telnet_login_never_logs_password(caplog, mocker):
    """Bug fix: the Telnet login password was logged (and saved in telnet.log)."""
    caplog.set_level(0)
    tn = SageTelnet("192.0.2.72")
    tn.PRE_WRITE_SLEEP = tn.POST_WRITE_SLEEP = 0
    sock = mocker.MagicMock()
    tn._comm.sock = sock
    tn.connected = True
    mocker.patch.object(tn, "read_until", return_value="")
    mocker.patch.object(tn, "read", return_value="->")
    try:
        assert tn.login("Admin", "SageTelnetCanary9")
    finally:
        tn.connected = False

    assert b"SageTelnetCanary9\r\n" in [c.args[0] for c in sock.sendall.call_args_list]
    assert "<redacted>" in caplog.text
    assert "SageTelnetCanary9" not in caplog.text


def test_bootline_password_redacted():
    raw = "ata=0,0(0,0)host:/ata0a/vxWorks e=192.0.2.10:ffffff00 u=target pw=Secr3t tn=sage"
    info = sage_parse.bootline_parse(raw)
    assert "pw" not in info
    assert info["password_set"] is True
    assert "Secr3t" not in str(info)
    assert sage_parse.bootline_parse({"pw": "", "tn": "sage"}) == {
        "password_set": False,
        "target_name": "sage",
    }

    version = sage_commands.parse_vxworks_version(
        "VxWorks (for Sage) version 6.9.\nKernel: WIND version 2.13.\n"
        f"Made on Jan 21 2015, 10:00:00.\nBoot line:\n{raw}"
    )
    assert version["raw_bootline"].endswith("u=target pw=<redacted> tn=sage")
    assert version["password_set"] is True
    assert "Secr3t" not in str(version)

    dev = DeviceData()
    sage_parse.process_bootline(dev, {"raw_bootline": raw})
    assert "Secr3t" not in dev.firmware.extra["bootline"]
    assert "pw=<redacted>" in dev.firmware.extra["bootline"]


def test_parse_ether_password_not_stored():
    xml = b"""<ETHERNET><PORT ID="1" NAME="fei0" Password="hunter2"><ROUTES/></PORT>
      <PORT ID="2" NAME="fei1" Password=""><ROUTES/></PORT></ETHERNET>"""
    info = {}
    sage_parse.parse_ether(io.BytesIO(xml), info)
    assert "hunter2" not in str(info)
    assert info["ethernet"]["entry_0"]["password_set"] is True
    assert info["ethernet"]["entry_1"]["password_set"] is False
    assert info["ethernet"]["entry_0"]["NAME"] == "fei0"


def test_parse_ether_routes_not_aliased():
    xml = b"""<ETHERNET>
      <PORT ID="1" NAME="fei0">
        <ROUTES>
          <ROUTE ID="1" DEST="10.1.0.0" MASK="255.255.0.0" GATEWAY="192.0.2.1"/>
          <ROUTE ID="2" DEST="198.51.100.0" MASK="255.255.255.0" GATEWAY="192.0.2.2" METRIC="2"/>
          <ROUTE ID="3" DEST="" MASK="" GATEWAY=""/>
        </ROUTES>
      </PORT>
      <PORT ID="2" NAME="fei1"/>
      <PORT ID="3" NAME="fei2"><ROUTES/></PORT>
    </ETHERNET>"""
    info = {}
    sage_parse.parse_ether(io.BytesIO(xml), info)
    entry = info["ethernet"]["entry_0"]
    assert entry["route_1"]["DEST"] == "10.1.0.0"
    assert entry["route_2"]["DEST"] == "198.51.100.0"
    assert entry["route_1"] is not entry["route_2"]
    # an element without routes no longer shifts/overwrites the following entries
    assert set(info["ethernet"]) == {"entry_0", "entry_1", "entry_2"}

    routes = sage_parse.routes_from_ethernet(info["ethernet"])
    assert [(r.destination, r.gateway, r.metric) for r in routes] == [
        ("10.1.0.0/16", "192.0.2.1", None),
        ("198.51.100.0/24", "192.0.2.2", 2),
    ]
    assert all(r.type == "static" for r in routes)
    assert routes[0].extra["route_id"] == "1"

    dev = DeviceData()
    for route in routes:
        dev.store("routes", route)
    dev.populate_fields()
    gateways = {r.remote.ip for r in dev.relationships if r.type == "routes_via"}
    assert gateways == {"192.0.2.1", "192.0.2.2"}


def test_bootline_default_route():
    dev = DeviceData()
    sage_parse.process_bootline(
        dev,
        sage_parse.bootline_parse(
            "ata=0,0(0,0)host:/ata0a/vxWorks e=192.0.2.10:ffffff00 g=192.0.2.1 tn=sage"
        ),
    )
    assert dev.interface[0].ip == "192.0.2.10"
    assert dev.interface[0].subnet_mask == "255.255.255.0"
    assert len(dev.routes) == 1
    assert dev.routes[0].destination == "0.0.0.0/0"
    assert dev.routes[0].gateway == "192.0.2.1"


def test_time_settings():
    xml = b"""<ROOT>
      <TIME SOURCE="GPS" UTCOFFSET="-07:00">
        <SNTP SERVER1="192.0.2.50" SERVER2="192.0.2.51" SERVER3="0.0.0.0" ENABLED="Y"/>
        <IRIG ENABLED="N"/>
      </TIME>
      <GBLFRZ INTERVAL="60"/>
      <GPS PORT="3" BAUD="9600"/>
    </ROOT>"""
    info = {}
    sage_parse.parse_time(io.BytesIO(xml), info)
    clock = sage_parse.clock_from_time_settings(info["time_settings"], info["gps_settings"])
    by_proto = {}
    for src in clock["sources"]:
        by_proto.setdefault(src.protocol, []).append(src)
    assert [(s.address, s.priority) for s in by_proto["sntp"]] == [
        ("192.0.2.50", 1),
        ("192.0.2.51", 2),
    ]
    assert by_proto["irig_b"][0].enabled is False
    assert by_proto["gps"][0].address == ""
    assert clock["source"] == "gps"
    assert clock["utc_offset"] == "-07:00"

    dev = DeviceData()
    sage_parse.process_time_settings(dev, info)
    sage_parse.process_time_settings(dev, info)  # idempotent
    assert len(dev.clock.sources) == 4
    assert dev.clock.source == "gps"
    dev.populate_fields()
    synced = {r.remote.ip for r in dev.relationships if r.type == "syncs_time_from"}
    assert synced == {"192.0.2.50", "192.0.2.51"}

    # Unknown layouts produce nothing (no guessing)
    empty = sage_parse.clock_from_time_settings({"MODE": 1}, {})
    assert empty == {"sources": []}


def test_baseline_reports_a_configured_time_source_change():
    """The time.xml SOURCE is configuration, not a live value (R4-0)."""
    from peat.api.baseline_api import create_baseline

    def rtu(source: str) -> DeviceData:
        xml = f"""<ROOT><TIME SOURCE="{source}" UTCOFFSET="-07:00">
          <SNTP SERVER1="192.0.2.50" ENABLED="Y"/><IRIG ENABLED="Y"/>
        </TIME><GBLFRZ INTERVAL="60"/><GPS PORT="3" BAUD="9600"/></ROOT>""".encode()
        info = {}
        sage_parse.parse_time(io.BytesIO(xml), info)
        dev = DeviceData(id="192.0.2.10", ip="192.0.2.10")
        sage_parse.process_time_settings(dev, info)
        return dev

    gps, internal = rtu("GPS"), rtu("INTERNAL")
    assert (gps.clock.source, internal.clock.source) == ("gps", "internal")
    for kind in ("first_observed", "approved", "engineer_provided"):
        baseline = create_baseline(gps, kind=kind)
        assert compare_device(rtu("GPS"), baseline) == []
        findings = compare_device(internal, baseline, include_passed=False)
        assert [(f.difference, f.path) for f in findings] == [("change", "clock.source")]


def test_led_definitions():
    xml = b"""<ROOT><LEDS>
      <LED NUM="1" DESC="COMM FAIL" PNT="RTU_STS_12" COLOR="RED" BLINK="Y"/>
      <LED NUM="2" DESC="TIME SYNC"/>
    </LEDS></ROOT>"""
    info = {}
    sage_parse.parse_leds(io.BytesIO(xml), info)
    leds = {i.name: i for i in sage_parse.indicators_from_leds(info["leds"])}
    assert leds["1"].type == "led"
    assert leds["1"].label == "COMM FAIL"
    assert leds["1"].equation == "RTU_STS_12"
    assert leds["1"].color == "red"
    assert leds["1"].position == "1"
    assert leds["1"].extra == {"BLINK": True}
    assert leds["1"].state == ""
    assert leds["1"].timestamp is None
    assert leds["2"].label == "TIME SYNC"


def test_serial_ports():
    xml = b"""<PORT VER="1" PNT="COM2" NAME="SCADA">
      <PROTOCOL TYPE="DNP3_S">
        <COMM BAUD="9600" PARITY="N" DATABITS="8" STOPBITS="1" RTS="Y"/>
        <DNP3_S RTU_ADDR="10" MASTER_ADDR="3" CONFIRM="Y"/>
      </PROTOCOL>
    </PORT>"""
    unused = b"""<PORT VER="1" PNT="COM3"><PROTOCOL TYPE="NONE"/></PORT>"""
    info = {}
    sage_parse.parse_port(io.BytesIO(xml), info)
    sage_parse.parse_port(io.BytesIO(unused), info)

    dev = DeviceData()
    sage_parse.process_ports(dev, info["ports"])

    ifaces = {i.name: i for i in dev.interface}
    com2 = ifaces["COM2"]
    assert com2.type == "serial"
    assert com2.application == "dnp3"
    assert (com2.baudrate, com2.parity, com2.data_bits, com2.stop_bits) == (9600, "none", 8, 1)
    assert com2.extra["comm_settings"] == {"RTS": True}
    assert com2.extra["NAME"] == "SCADA"
    assert com2.services[0].protocol == "dnp3"
    assert ifaces["COM3"].application == ""

    svc = dev.service[0]
    assert svc.protocol == "dnp3"
    assert svc.role == "outstation"
    assert svc.listen_interface == "COM2"
    assert svc.port is None

    rel = dev.relationships[0]
    assert rel.protocol == "dnp3"
    assert rel.medium == "serial"
    assert rel.local.serial_port == "COM2"
    assert rel.local.role == "outstation"
    assert rel.local.protocol_address == "10"
    assert rel.remote.role == "master"
    assert rel.remote.protocol_address == "3"
    assert rel.direction == "ingress"  # the remote master polls
    assert rel.evidence == {"config"}

    assert sage_parse.canonical_port_protocol("MODBUS_M") == "modbus_rtu"


@pytest.mark.parametrize(
    ("proto_type", "attrs", "roles", "direction"),
    [
        ("MODBUS_M", 'SLAVE_ADDR="7"', ("client", "server"), "egress"),
        (
            "IEC101_MASTER",
            'REMOTE_ADDR="7"',
            ("controlling_station", "controlled_station"),
            "egress",
        ),
        (
            "IEC101_SLAVE",
            'MASTER_ADDR="7"',
            ("controlled_station", "controlling_station"),
            "ingress",
        ),
        ("CONITEL", 'REMOTE_ADDR="7"', ("", ""), ""),
    ],
)
def test_serial_port_relationship_direction(proto_type, attrs, roles, direction):
    xml = f"""<PORT VER="1" PNT="COM4"><PROTOCOL TYPE="{proto_type}">
        <COMM BAUD="9600"/><{proto_type} {attrs}/></PROTOCOL></PORT>""".encode()
    info = {}
    sage_parse.parse_port(io.BytesIO(xml), info)
    dev = DeviceData()
    sage_parse.process_ports(dev, info["ports"])
    (rel,) = dev.relationships
    assert (rel.local.role, rel.remote.role) == roles
    assert rel.remote.protocol_address == "7"
    assert rel.direction == direction
    assert sage_parse.canonical_port_protocol("IEC101") == "iec101"
    assert sage_parse.canonical_port_protocol("Conitel 2020") == "conitel_2020"


def _log(lines: list[str]) -> io.BytesIO:
    return io.BytesIO("\n".join(lines).encode())


def test_log_events_reason_action():
    info = {}
    sage_parse.parse_logfiles(
        _log(
            [
                '<REC ID="5" DT="01/01/2025" TM="00:00:00.000" VAL="1" '
                'PN="TIME SRC FAIL" DN="RTU Internal Status"/>',
                '<REC ID="6" DT="01/01/2025" TM="00:00:05.000" VAL="0" '
                'PN="TIME SRC FAIL" DN="RTU Internal Status"/>',
                '<REC ID="7" DT="01/01/2025" TM="00:00:06.000" TYPE="Logged In" '
                'TXT="192.0.2.20-FTP, Admin, LCL_DB"/>',
            ]
        ),
        info,
    )
    dev = DeviceData(ip="192.0.2.10")
    sage_parse.process_logfile_events(dev, info["raw_events"])
    events = {e.sequence: e for e in dev.event}

    assert events[5].reason == "TIME SRC FAIL"
    assert events[5].action == "set"
    assert events[5].dataset == "soelog"
    assert events[6].action == "clear"
    assert events[7].reason == "192.0.2.20-FTP, Admin, LCL_DB"
    assert events[7].dataset == "userlog"
    assert events[7].action == "logged-in"
    assert "authentication" in events[7].category


def test_ipcom_syslog_log_level():
    info = {}
    sage_parse.parse_ipcom_syslog(
        _log(["Jan 01 00:00:01: iptelnets[0x1d02b10]: Error: ipcom_telnet: login failed"]),
        info,
    )
    dev = DeviceData(ip="192.0.2.10")
    sage_parse.process_ipcom_syslog(dev, info["ipcom_syslog_events"])
    event = dev.event[0]
    assert event.log_level == "error"
    assert "level" not in event.extra
    assert event.extra["task_id"] == "0x1d02b10"


def test_netstat_has_task_ids():
    with_tid = (
        "INET sockets\n"
        "Prot Recv-Q Send-Q Local Address         Foreign Address       (state)      TID\n"
        "TCP       0      0 0.0.0.0.23            0.0.0.0.*             LISTEN       0x1d02b10\n"
    )
    without_tid = (
        "INET sockets\n"
        "Prot Recv-Q Send-Q Local Address         Foreign Address       (state)\n"
        "TCP       0      0 0.0.0.0.23            0.0.0.0.*             LISTEN\n"
    )
    assert sage_parse.netstat_has_task_ids(with_tid)
    assert not sage_parse.netstat_has_task_ids(without_tid)
    assert not sage_parse.netstat_has_task_ids("")


def test_file_inventory():
    assert sage_parse.file_categories("/ata0a/scripts/startup.scp") == {"script"}
    assert sage_parse.file_categories("/ata0a/Webfiles/LOGS/SYSLOG.LOG") == {"log"}
    assert sage_parse.file_categories("/ata0a/ipcom/syslog.0") == {"log"}
    assert sage_parse.file_categories("/ata0a/Webfiles/xml/port1.xml") == {"configuration"}
    assert sage_parse.file_categories("/ata0a/ssl/cert/server.crt") == {"certificate"}
    assert sage_parse.file_categories("/ata0a/ssl/private/server.key") == {"key"}
    assert sage_parse.file_categories("/ata0a/vxWorks") == {"firmware"}
    assert sage_parse.file_categories("/ata0a/readme.bin") == set()

    modified = datetime(2011, 1, 21, 0, 0)
    listing = [
        {
            "type": "file",
            "permissions": "rwxrwxrwx",
            "size": 437,
            "modified": modified,
            "name": "startup.scp",
            "path": "/ata0a/scripts/startup.scp",
            "parent": "/ata0a/scripts/",
        },
        {
            "type": "dir",
            "permissions": "rwxr-xr-x",
            "size": 8192,
            "modified": modified,
            "name": "scripts",
            "path": "/ata0a/scripts",
            "parent": "/ata0a/",
        },
    ]
    files = sage_parse.listing_to_files(listing)
    assert files[0].path == PurePosixPath("/ata0a/scripts/startup.scp")
    assert files[0].mode == "0777"
    assert files[0].size == 437
    assert files[0].mtime == modified
    assert files[0].category == {"script"}
    assert files[0].local_path is None
    assert files[1].type == "dir"
    assert files[1].size is None
    assert files[1].mode == "0755"

    member = tarfile.TarInfo("xml/port1.xml")
    member.size = 120
    member.mode = 0o644
    member.mtime = 1_700_000_000
    tar_file = sage_parse.tar_member_to_file(member, "RTU_Config.tar.gz")
    assert tar_file.path == PurePosixPath("xml/port1.xml")
    assert tar_file.mode == "0644"
    assert tar_file.mtime == datetime.fromtimestamp(1_700_000_000, tz=UTC)
    assert tar_file.category == {"configuration"}
    assert tar_file.extra == {"archive": "RTU_Config.tar.gz"}

    dev = DeviceData()
    dev.store("files", files[0], lookup="path")
    dev.store("files", files[0].copy(deep=True), lookup="path")
    assert len(dev.files) == 1


@pytest.mark.usefixtures("out_config")
def test_parse_config_tar(tmp_path):
    rtusetup = b"<RTU_SETUP><CPU><RTU><NAME>ChangeMe</NAME></RTU></CPU></RTU_SETUP>"
    isagraf = b"ISaGRAF 5.21\r\n"
    tar_path = tmp_path / "RTU_Config.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        for name, data in [("xml/rtusetup.xml", rtusetup), ("isagraf/ISaGRAF.TXT", isagraf)]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))

    dev = Sage.parse(tar_path)
    assert dev.extra["rtusetup_placeholders"] == ["RTU/NAME"]
    assert "rtusetup_info" not in dev.extra
    assert {str(f.path) for f in dev.files} == {"xml/rtusetup.xml", "isagraf/ISaGRAF.TXT"}
    assert dev.software[0].name == "ISaGRAF"
    assert dev.software[0].version == "5.21"


@pytest.mark.usefixtures("out_config")
def test_parse_config_tar_member_cannot_escape(tmp_path):
    tar_path = tmp_path / "in" / "config.tar.gz"
    tar_path.parent.mkdir()
    rtusetup = b"<RTU_SETUP><CPU><RTU><NAME>RTU1</NAME></RTU></CPU></RTU_SETUP>"
    # A name no other test writes: the search below covers the tmp directories of
    # every test of this worker, and Windows globbing ignores case.
    canary = "sage-tar-member-escaped-canary.txt"
    with tarfile.open(tar_path, "w:gz") as tar:
        for name, data in [("xml/rtusetup.xml", rtusetup), (f"../../../../{canary}", b"x")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    Sage.parse(tar_path)
    assert list(tmp_path.parent.rglob(canary)) == []


@pytest.mark.usefixtures("out_config")
def test_parse_config_tar_out_of_range_mtime(tmp_path):
    """A corrupt member time no longer aborts the parse of the whole archive."""
    tar_path = tmp_path / "in" / "config.tar.gz"
    tar_path.parent.mkdir()
    rtusetup = b"<RTU_SETUP><CPU><RTU><NAME>ChangeMe</NAME></RTU></CPU></RTU_SETUP>"
    _write_tar(tar_path, {"xml/rtusetup.xml": rtusetup}, mtime=10**15)

    dev = Sage.parse(tar_path)
    assert dev.extra["rtusetup_placeholders"] == ["RTU/NAME"]
    assert [str(f.path) for f in dev.files] == ["xml/rtusetup.xml"]
    assert dev.files[0].mtime is None

    member = tarfile.TarInfo("x.xml")
    member.mtime = 10**15
    assert sage_parse.tar_member_to_file(member, "a.tar.gz").mtime is None
    attrs = SimpleNamespace(filename="x.xml", st_size=1, st_mtime=10**15, longname="")
    assert sage_parse.sftp_attrs_to_file("/ata0a", attrs).mtime is None


def test_parse_config_tar_without_extraction_filter(out_config, monkeypatch):
    """Without the tarfile "data" filter (Python < 3.11.4) nothing is extracted unfiltered."""
    tar_path = out_config / "in" / "config.tar.gz"
    tar_path.parent.mkdir()
    rtusetup = b"<RTU_SETUP><CPU><RTU><NAME>RTU1</NAME></RTU></CPU></RTU_SETUP>"
    _write_tar(tar_path, {"xml/rtusetup.xml": rtusetup})
    monkeypatch.delattr(tarfile, "data_filter")

    dev = Sage.parse(tar_path)
    assert dev.files
    assert list((out_config / "devices").rglob("*_raw_files")) == []


def test_downloaded_file_local_path_stays_in_download_dir(tmp_path):
    """A device path with ".." gets the local path that the download actually used."""
    ftp_dir = tmp_path / "ftp_files"
    (ftp_dir / "etc").mkdir(parents=True)
    (ftp_dir / "etc" / "hostname").write_text("x")
    outside = tmp_path / "etc"
    outside.mkdir()
    (outside / "hostname").write_text("y")

    device_path = "/../../etc/hostname"
    listing = [{"type": "file", "name": "hostname", "path": device_path}]
    files = sage_parse.listing_to_files(listing, local_dir=ftp_dir, downloaded={device_path})
    assert files[0].local_path == ftp_dir / "etc" / "hostname"

    attrs = SimpleNamespace(filename="hostname", st_size=1, st_mtime=None, longname="")
    sftp_file = sage_parse.sftp_attrs_to_file("/../../etc", attrs, local_dir=ftp_dir)
    assert sftp_file.local_path == ftp_dir / "etc" / "hostname"


def test_record_login_default_credentials():
    dev = DeviceData(ip="192.0.2.10")
    Sage._record_login(dev, "telnet", "admin", "Telvent1!")
    svc = dev.retrieve("service", {"protocol": "telnet"})
    assert svc.port == 23
    assert svc.security.default_credentials is True
    assert svc.security.authentication_required is True

    dev2 = DeviceData(ip="192.0.2.11")
    Sage._record_login(dev2, "ftp", "Admin", "site-password")
    svc2 = dev2.retrieve("service", {"protocol": "ftp"})
    assert svc2.security.default_credentials is None  # only one credential was tried


def test_known_defaults():
    baselines = Sage.get_known_defaults()
    assert [b.id for b in baselines] == ["sage-vendor-recommended"]
    baseline = baselines[0]
    assert baseline.kind == "vendor_recommended"
    assert baseline.expected is None
    ids = [r.id for r in baseline.rules]
    assert len(ids) == len(set(ids))
    for rule in baseline.rules:
        assert split_path(rule.path)

    dev = DeviceData(ip="192.0.2.10", type="RTU")
    dev.description.vendor.id = "Schneider"
    Sage._record_login(dev, "telnet", "Admin", "Telvent1!")
    dev.extra["rtusetup_placeholders"] = ["RTU/NAME"]
    results = {f.rule_id: f for f in compare_device(dev, baseline)}
    assert results["sage.service.telnet.absent"].result == "fail"
    assert results["sage.service.ftp.absent"].result == "pass"
    assert results["sage.accounts.default-credentials"].result == "fail"
    assert results["sage.accounts.default-credentials"].alert
    assert results["sage.settings.placeholders"].result == "fail"
