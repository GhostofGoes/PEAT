"""
Tests for the additional read-only SEL ASCII commands: the command registry and
the commands PEAT refuses to send (sel_commands.py), the parsers of the new commands
(relay_command_parse.py), and SELRelay.pull_more_commands (sel_more_commands.py),
against the scripted relay in fake_sel_relay.py with the canned outputs in
sel_command_transcripts.py. No hardware is needed, and all data is synthetic.
"""

import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from peat import SELRelay, config, datastore
from peat.modules.sel import sel_ascii, sel_commands
from peat.modules.sel.relay_command_parse import (
    goose_peer_names,
    help_lists_commands,
    parse_cascii_names,
    parse_cst_output,
    parse_goose_output,
    parse_help_output,
    parse_selogic_usage,
    parse_status_details,
    parse_time_quality,
)
from peat.modules.sel.relay_parse import parse_and_process_events
from peat.modules.sel.sel_ascii import SELAscii, SELResponse, mac_result_key
from peat.modules.sel.sel_commands import (
    COMMANDS,
    COMMANDS_2030,
    SHOW_SETTINGS_DEFAULT,
    SELCommandRefused,
    check_command,
    command_refusal,
    is_read_only,
    listed,
    normalize_command,
    ser_command,
    show_settings_commands,
)
from peat.modules.sel.sel_more_commands import MoreCommands, show_result_name
from peat.modules.sel.sel_serial import SELSerial
from peat.modules.sel.sel_telnet import SELTelnet

from . import sel_command_transcripts as tr
from .fake_sel_relay import FakeSELRelay, FakeSerialPort, TCPRelayServer


@pytest.fixture(autouse=True)
def env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp",
        },
    )
    mocker.patch.object(datastore, "objects", [])
    mocker.patch.object(SELAscii, "FIRST_COMMAND_QUIET", 0.0)
    mocker.patch.object(SELAscii, "_failed_passwords", {})
    mocker.patch.object(SELAscii, "_good_passwords", {})
    mocker.patch.object(SELAscii, "_unsupported_commands", {})


@pytest.fixture
def relay_server():
    servers = []

    def _make(factory=None, **kwargs) -> TCPRelayServer:
        server = TCPRelayServer(factory or FakeSELRelay, **kwargs)
        servers.append(server)
        return server

    yield _make
    for server in servers:
        server.close()


def _telnet(server: TCPRelayServer) -> SELTelnet:
    return SELTelnet("127.0.0.1", server.port, timeout=2.0)


def _dev(model: str = "", fid: str = "", ident: str = "127.0.0.1"):
    dev = datastore.get(ident, "ip")
    if model:
        dev.description.model = model
    if fid:
        dev.firmware.id = fid
    return dev


def _sent(relay: FakeSELRelay) -> list[str]:
    """The commands the relay received, without the passwords and empty lines."""
    passwords = {p for p in relay.passwords.values() if p}
    return [line.decode() for line in relay.lines if line and line.decode() not in passwords]


def _pull(server: TCPRelayServer, dev) -> tuple[bool, SELTelnet, FakeSELRelay]:
    tn = _telnet(server)
    # pull_telnet() logs in to level 1 before it runs the commands
    assert tn.elevate(1)
    result = SELRelay.pull_more_commands(dev, tn)
    tn.disconnect()
    return result, tn, server.relays[-1]


def _file(dev, name: str):
    return next(f for f in dev.files if f.name == name)


# ---------------------------------------------------------------------------
# Commands that PEAT refuses to send
# ---------------------------------------------------------------------------

#: Commands that change the state of a relay, from the command tables of the
#: SEL-351S, SEL-421, SEL-751A, and SEL-2032 manuals, and the command summaries
#: of the SEL-710 IM 20090327 (motor), SEL-749M IM 20080918 (motor), and
#: SEL-700G IM 20150521 (generator) manuals
DENIED = [
    "SER C",
    "SER CV",
    "ser cv",
    "SER R",
    "SER CA",
    "SER GLOBAL C",
    "HIS C",
    "HIS CA",
    "SUM ACK",
    "SUM C",
    "CEV ACK",
    "CSU ACK",
    "TAR R",
    "MET RD",
    "MET RE",
    "MET 1 R",
    "ETH C",
    "COM A C",
    "GOO S ALL C",
    "BRE R",
    "BRE 1 C",
    "LDP C",
    "SSI T",
    "TRI",
    "TRIGGER 12:00:00",
    "IRI",
    "DAT 01/01/2024",
    "DATE 2024/01/01",
    "TIM 12:00:00",
    "STA C",
    "STATUS R",
    "STA SC",
    "L_D",
    "LD",
    "R_S",
    "PAS",
    "PAS 1 OTTER",
    "SET",
    "SET P 5",
    "SET L 1",
    "CAL",
    "COP 1 2",
    "PAR",
    "GRO 2",
    "FIL WRITE SET_1.TXT",
    "FILE WRITE SETTINGS SET_1.TXT",
    "OPE 1",
    "CLO 1",
    "PUL OUT101",
    "CON RB01",
    "TEST DB",
    "PORT 5",
    "BROADCAST",
    "Y",
    "yes",
    # SEL-710 and SEL-749M: start or stop the motor, reset learned parameters,
    # clear motor statistics and start trends (level 2)
    "STR",
    "STO",
    "RLP",
    "MOT R",
    "MOT C",
    "MST R",
    "MST C",
    # SEL-700G: auto-synchronizing, synchronism report trigger, curve download,
    # energy preload
    "AST",
    "ASP",
    "GST",
    "DTO",
    "MET WE",
    "GEN R",
    "SYN R",
    # SEL-421 Table 9.46: DNP param sets the serial port DNP3 settings
    "DNP 1",
    "DNP SET",
    # Longer forms of the arguments that clear or reset, and of Y
    "STA CL",
    "STA RS",
    "STATUS CLEAR",
    "SER CVX",
    "SER RESET",
    "HIS CLEAR",
    "SUM ACKN",
    "EVE ACKNOWLEDGE",
    "TAR RESET",
    "MET RDX",
    "BRE RESET",
    "COM CLEAR A",
    "YE",
    "YEAH",
    "Yes please",
]


@pytest.mark.parametrize("command", DENIED)
def test_denied_commands_are_refused(command, mocker):
    assert command_refusal(command).startswith("it may change the state of the device")
    with pytest.raises(SELCommandRefused):
        check_command(command)
    assert not is_read_only(command)

    # Every write goes through SELAscii._send(), which refuses it before anything is sent
    tn = SELTelnet("192.0.2.80")
    write = mocker.patch.object(tn, "_write_raw")
    with pytest.raises(SELCommandRefused):
        tn.write(command)
    with pytest.raises(SELCommandRefused):
        tn.run_command(command)
    with pytest.raises(SELCommandRefused):
        tn.run_read_command(command)
    write.assert_not_called()
    assert tn.all_writes == []


@pytest.mark.parametrize(
    "command",
    [
        "MET RMS",  # SEL-700 series: RMS metering
        "MET PM",
        "MOT",
        "MST",
        "MSR 1",
        "DNP",
        "DNP VIEW",
        "DNPMAP",
        "EVE 1 A",  # SEL-351S: analog section only
        "SER D",  # SEL-751A: SER delete report
        "SER 01/01/2024",
        "STA S",
        "STA A",
        "VEC D",
        "COU 1",
        "N",
    ],
)
def test_read_only_forms_are_not_refused(command):
    # Read-only forms of commands that also have state-changing forms
    assert command_refusal(command) == ""


def test_sensitive_writes_are_checked(mocker):
    # Only the answer to a password prompt (in elevate()) isn't checked
    tn = SELTelnet("192.0.2.84")
    write = mocker.patch.object(tn, "_write_raw")
    with pytest.raises(SELCommandRefused) as ex:
        tn.write("STA C", sensitive=True)
    assert "STA C" not in str(ex.value)
    assert "<redacted>" in str(ex.value)
    write.assert_not_called()

    tn._send_password("STA C")
    write.assert_called_once_with(b"STA C\r\n", sensitive=True)
    assert tn.all_writes == [b"<redacted>\r\n"]
    # Only while the password is sent
    with pytest.raises(SELCommandRefused):
        tn.write("STA C", sensitive=True)


def test_state_changes_only_in_the_internal_context(mocker):
    tn = SELTelnet("192.0.2.81")
    write = mocker.patch.object(tn, "_write_raw")
    with tn._allow_state_changes("test"):
        tn.write("STA C")
        tn.write("Y")
    write.assert_any_call(b"STA C\r\n", sensitive=False)
    write.assert_any_call(b"Y\r\n", sensitive=False)

    # The context ends with the block
    with pytest.raises(SELCommandRefused):
        tn.write("Y")


def test_line_breaks_and_raw_data_are_refused(mocker):
    tn = SELTelnet("192.0.2.82")
    write = mocker.patch.object(tn, "_write_raw")
    for command in ("ID\rSER C", "ID\nSTA C", "VER\x00"):
        assert "control characters" in command_refusal(command)
        with pytest.raises(SELCommandRefused):
            tn.write(command)
    # Only CAN is sent without a line terminator
    with pytest.raises(SELCommandRefused):
        tn._send("SER C", terminator=False)
    tn._send(b"\x18", terminator=False)
    write.assert_called_once_with(b"\x18", sensitive=False)


def test_unknown_commands_are_only_refused_with_strict(mocker):
    tn = SELTelnet("192.0.2.83")
    mocker.patch.object(tn, "_write_raw")
    assert command_refusal("XYZ") == ""
    assert "isn't one of the read-only commands" in command_refusal("XYZ", strict=True)
    tn.write("XYZ")  # e.g. a test of the "Invalid Command" handling
    with pytest.raises(SELCommandRefused):
        tn.run_read_command("XYZ")
    with pytest.raises(SELCommandRefused):
        tn.run_read_command("MET")  # Read-only, but not a command PEAT uses


@pytest.mark.parametrize(
    "model", ["351S", "311C", "421", "451", "487E", "751A", "700G", "710", "2411", "2032", ""]
)
def test_registry_commands_are_read_only(model):
    for spec in [*COMMANDS.values(), *COMMANDS_2030.values()]:
        command = spec.command_for(model)
        assert is_read_only(command), command
        assert command_refusal(command, strict=True) == ""
    for command in show_settings_commands(SHOW_SETTINGS_DEFAULT, "1"):
        assert is_read_only(command), command


@pytest.mark.parametrize(
    "command",
    [
        "",
        "N",
        "id",
        "acc",
        "2ac",
        "quit",
        "exit",
        "fil dir",
        "fil dir SETTINGS",
        "fil show SETTINGS SET_1.TXT",
        "file show",
        "fil read CFG.TXT",
        "date",
        "time",
        "gro",
        "sta",
        "sta s",
        "ser",
        "ser GLOBAL 100",
        "his",
        "sum",
        "eve",
        "bre",
        "mac",
        "eth",
        "dnpmap",
        "who",
        "status",
        "card 17",
        "TIME Q",
        "GOOSE",
        "SHO P 5",
        "SHO DNP 1",
        "HELP SER",
    ],
)
def test_commands_peat_uses_are_allowed(command):
    assert is_read_only(command)


def test_normalize_command():
    assert normalize_command("  status   a ") == "STA A"
    assert normalize_command("2ACCESS") == "2AC"
    assert normalize_command("file show settings set_1.txt") == "FIL SHO SETTINGS SET_1.TXT"
    assert normalize_command("") == ""
    assert sel_commands.command_key("GOOSE S 1") == "GOO"
    assert listed("CSER", {"CSE": {}})
    assert listed("GOOSE", ["GOO", "SER"])
    assert not listed("CST", ["CSE"])


def test_ser_command_by_family():
    # SEL-421 IM 20130627 Table 9.96: SER without arguments only returns 20 records
    assert ser_command("451") == "SER 1000"
    assert ser_command("SEL-421-5-R310") == "SER 1000"
    assert ser_command("487E") == "SER 1000"
    assert ser_command("351S") == "SER"
    assert ser_command("751A") == "SER"
    assert ser_command("2032") == "SER GLOBAL 100"
    assert ser_command("") == "SER"


def test_show_settings_commands():
    assert show_settings_commands(SHOW_SETTINGS_DEFAULT, "2") == [
        "SHO G",
        "SHO 2",
        "SHO L 2",
        "SHO P",
        "SHO R",
    ]
    # Without the group, the relay shows the active group
    assert show_settings_commands(SHOW_SETTINGS_DEFAULT) == [
        "SHO G",
        "SHO",
        "SHO L",
        "SHO P",
        "SHO R",
    ]
    assert show_result_name("SHO L 1") == "sho_l_1"
    assert show_result_name("SHO") == "sho"


def test_passwords_are_not_checked(relay_server):
    # "Passw0rd" is "PAS" (change passwords) as a command, but it's a password
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "Passw0rd"}))
    tn = _telnet(server)
    assert tn.elevate(1, {"acc": "Passw0rd"})
    assert tn.access_level == "1"
    tn.disconnect()


def test_change_active_group_confirms_in_the_context(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="2"))
    tn = _telnet(server)
    tn.change_active_group("2")
    relay = server.relays[0]
    assert relay.answers == [("GRO 2", "Y")]
    assert relay.group == "2"
    # Nothing else may confirm a question
    with pytest.raises(SELCommandRefused):
        tn.write("Y")
    tn.disconnect()


def test_level_c_login_in_the_context(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="2"))
    tn = _telnet(server)
    assert tn.elevate(3)
    assert tn.access_level == "C"
    with pytest.raises(SELCommandRefused):
        tn.write("CAL")
    tn.disconnect()


def test_invalid_command_is_remembered(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="1", fid=tr.FID_351S))
    tn = _telnet(server)
    tn.fid = tr.FID_351S
    first = tn.run_read_command("VER")
    assert first.error == "Invalid Command"
    assert not first.skipped
    second = tn.run_read_command("ver")
    assert second.skipped
    assert second.error == "Invalid Command"
    tn.disconnect()
    assert _sent(server.relays[0]).count("VER") == 1

    # A new session for a device with the same FID doesn't send it (or connect)
    tn = _telnet(server)
    tn.fid = tr.FID_351S
    assert tn.run_read_command("VER").skipped
    tn.disconnect()
    assert len(server.relays) == 1

    # Only for this device: another relay with the same firmware gets the command
    other = SELTelnet("192.0.2.85")
    other.fid = tr.FID_351S
    assert not other.is_unsupported("VER")

    # Forgotten at the start of a pull (or restart) of the device, e.g. if the
    # command was garbled on a noisy serial line
    SELRelay._forget_ascii_passwords(_dev("351S", tr.FID_351S))
    tn = _telnet(server)
    tn.fid = tr.FID_351S
    assert not tn.run_read_command("VER").skipped
    tn.disconnect()
    assert "VER" in _sent(server.relays[1])


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def test_parse_time_quality_351s():
    info = parse_time_quality("\r\n".join(tr.TIM_Q_351S))
    assert info == {
        "utc_time": "15:20:16",
        "utc_offset_hours": -5.0,
        "time_source": "OTHER",
        "last_update_source": "NONV CLK",
        "last_update_time": "08:00:01   04/12/24",
        "last_update": datetime(2024, 4, 12, 8, 0, 1),
        "internal_clock_period_ns": 20.000156,
    }


def test_parse_time_quality_421():
    info = parse_time_quality("\r\n".join(tr.TIME_Q_421))
    assert info == {
        "time_source": "HIRIG",
        "last_update_source": "HIRIG",
        "irig_time_mark_period_ms": 1000.0,
        "internal_clock_period_ns": 24.999995,
    }
    # The "Serial Number:" in the header isn't a value
    assert parse_time_quality("Station A      Serial Number: 1234") == {}


def test_parse_goose_output():
    info = parse_goose_output("\r\n".join(["=>GOO", *tr.GOO_351S, "=>"]))
    assert len(info["transmit"]) == 1
    assert len(info["receive"]) == 2

    sent = info["transmit"][0]
    assert sent == {
        "control_block": "SEL_351S_1CFG/LLN0$GO$GooseDSet13",
        "logical_device": "SEL_351S_1CFG",
        "ied_name": "SEL_351S_1",
        "multicast_address": "01:0C:CD:01:00:12",
        "priority": 4,
        "vlan": 1,
        "app_id": 4114,
        "state_number": "1",
        "sequence_number": "11175",
        "ttl_ms": 638,
        "code": "",
        "data_set": "SEL_351S_1CFG/LLN0$DSet13",
    }
    assert info["receive"][1]["code"] == "TTL EXPIRED"
    assert goose_peer_names(info) == ["SEL_351S_1", "SEL_487E_1"]


def test_parse_goose_output_without_appid():
    # SEL-751A IM 20130329 Figure 7.19: no AppID column, and another vendor's
    # logical device name that doesn't end with SEL's "CFG"
    text = "\n".join(
        [
            "GOOSE Receive Status",
            "   MultiCastAddr   Ptag:Vlan StNum       SqNum      TTL    Code",
            "-------------------------------------------------------------",
            "OTHER_IED_LD0/LLN0$GO$Gcb01",
            "   01-0C-CD-01-00-05 4:0      1          100425     160",
            "   Data Set: OTHER_IED_LD0/LLN0$DSet10",
        ]
    )
    info = parse_goose_output(text)
    assert info["transmit"] == []
    cb = info["receive"][0]
    assert cb["app_id"] is None
    assert cb["state_number"] == "1"
    assert cb["sequence_number"] == "100425"
    assert cb["ttl_ms"] == 160
    assert cb["ied_name"] == ""
    assert goose_peer_names(info) == ["OTHER_IED_LD0"]
    assert parse_goose_output("Invalid Command") == {"transmit": [], "receive": []}


def test_parse_help_output():
    names = parse_help_output("\r\n".join(["=>HELP", *tr.HELP_421, "=>"]))
    assert {"2AC", "ACC", "CAS", "CSE", "SER", "STA", "VER"} <= set(names)
    assert "HELP" not in names
    assert help_lists_commands(names)
    # SELBOOT style: "Baud  - Set the baud rate"
    assert parse_help_output("Baud     - Set the baud rate\r\nErase    - Erase") == [
        "BAUD",
        "ERASE",
    ]
    assert not help_lists_commands(parse_help_output("Invalid Command"))
    assert not help_lists_commands(["FEEDER", "STATION"])


def test_parse_status_details_351s():
    info = parse_status_details("\r\n".join(tr.STA_351S))
    assert info["relay_enabled"] is True
    tests = info["self_tests"]
    assert tests["OS_IA"] == -1.0
    assert tests["OSH_IN"] == 1.0
    assert tests["PS_3.3V_REG"] == 3.27
    assert tests["RAM"] == "OK"
    assert tests["A/D"] == "OK"
    assert tests["RTC"] == "OK"
    assert info["temperature_c"] == 32.2
    # Lines that aren't tables aren't read as names
    assert "W=Warn" not in tests
    assert "SELF" not in tests


def test_parse_status_details_751a():
    info = parse_status_details("\r\n".join(tr.STA_751A))
    tests = info["self_tests"]
    assert tests["CID_FILE"] == "OK"
    assert tests["+0.9V"] == 0.9
    assert tests["CARD_C"] == "OK"
    assert tests["VS"] == "OK"
    assert info["relay_enabled"] is True


def test_parse_status_details_421_sta_a():
    info = parse_status_details("\r\n".join(tr.STA_A_421))
    assert info["failures"] == []
    assert info["warnings"] == ["IO_BRD1 Warning"]
    assert info["temperature_c"] == 23.7
    assert info["time_sync_source"] == "IRIG-B"
    assert info["self_tests"]["CH2"] == 1.0
    assert info["self_tests"]["N15V_PS"] == -14.79
    assert parse_status_details("Relay Disabled") == {"relay_enabled": False}


def test_parse_selogic_usage():
    info = parse_selogic_usage("\r\n".join(tr.STA_S_751A))
    assert info == {
        "part_number": "751A01BBX5X7186030X",
        "usage_percent": {"Global": 81.0, "FP": 69.0, "Report": 96.0},
        "groups": {
            "1": {"Execution": 90.0, "Group": 81.0, "Logic": 89.0},
            "2": {"Execution": 90.0, "Group": 81.0, "Logic": 89.0},
            "3": {"Execution": 90.0, "Group": 81.0, "Logic": 89.0},
        },
    }
    assert parse_selogic_usage("No Errors") == {}


def test_parse_cascii_names():
    assert parse_cascii_names("SNS\r\n" + tr.SNS_351S) == [
        "TRIP",
        "51P1T",
        "51G1T",
        "67P1",
        "PB10",
        "OC",
        "CLOSE",
        "52A",
        "CF",
    ]
    assert parse_cascii_names(tr.BNA_351S)[5:7] == ["PWRUP", "STSET"]
    assert len(parse_cascii_names(tr.DNA_351S)) == 16
    # A record with a wrong checksum is skipped
    assert parse_cascii_names('"50A1","50B1","0000"\r\n') == []
    assert parse_cascii_names(tr.cascii([["No Data Available"]])) == []


def test_parse_cst_output():
    values = parse_cst_output(tr.CST_351S)
    assert values["FID"] == f"FID={tr.FID_351S}"
    assert values["YEAR"] == 2024
    assert values["RAM"] == "OK"
    assert values["TEMP"] == "32.2"


def test_show_mac_both_formats(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="1", outputs={"MAC": tr.MAC_351S}))
    tn = _telnet(server)
    # The keys of the (IP)/(GOOSE) format are the ones PEAT used before
    assert tn.show_mac() == {"ip_mac": "00:30:A7:01:09:2E", "goose_mac": "00:30:A7:01:09:2F"}
    tn.disconnect()

    server = relay_server(lambda: FakeSELRelay(level="1", outputs={"MAC": tr.MAC_751A}))
    tn = _telnet(server)
    assert tn.show_mac() == {"port_1_mac": "00:30:A7:00:75:6A"}
    tn.disconnect()
    assert mac_result_key("MAC 1") == "mac_1"


# ---------------------------------------------------------------------------
# pull_more_commands(): 300 series
# ---------------------------------------------------------------------------


def test_pull_more_commands_351s(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S))
    dev = _dev("351S", tr.FID_351S)

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)

    # Discovery before 2AC, then the commands in the same order as before, then the new ones
    assert sent[:5] == ["ACC", "HELP", "CAS", "2AC", "SER"]
    assert sent.index("SER") < sent.index("his") < sent.index("sta") < sent.index("date")
    assert sent.index("gro") < sent.index("SHO 1")
    assert "SHO L 1" in sent
    for command in ("VER", "TIM Q", "GOO", "SNS", "DNA X", "BNA", "CST", "SHO G", "SHO R"):
        assert command in sent
    # CAS doesn't list CSE on the 351S. It lists CHI, but HIS worked (as before).
    assert "CSE" not in sent
    assert "CHI" not in sent
    # Nothing that changes the state of the relay
    assert not [c for c in sent if not is_read_only(c)]
    assert relay.answers == []

    # Events: SER (with the power-up record) and HIS
    ser = [e for e in dev.event if e.dataset == "ser"]
    history = [e for e in dev.event if e.dataset == "history"]
    assert len(ser) == 3
    assert ser[0].extra["source_datasets"] == ["SER"]
    assert len(history) == 1
    assert history[0].extra["event"] == "AG T"
    assert history[0].extra["source_datasets"] == ["HIS"]
    assert dev.uptime == timedelta(hours=1, minutes=49, seconds=43, milliseconds=674)

    # Discovery
    assert dev.extra["compressed_ascii_commands"] == {"CST": 1, "CHI": 1, "CEV": 1}
    assert "ascii_commands" not in dev.extra  # HELP isn't a 351S command
    assert dev.extra["command_errors"]["help"] == "Invalid Command"
    assert dev.extra["skipped_commands"]["cse"] == "CAS doesn't list it"

    # Status, version, Ethernet, MAC, time, GOOSE, names, settings
    assert dev.extra["self_tests"]["RAM"] == "OK"
    assert dev.extra["temperature_c"] == 32.2
    assert dev.status == "enabled"
    assert dev.part_number == "0351S7XHD3E5462"
    assert dev.boot_firmware.checksum == "58FF"
    assert dev.extra["relay_features"] == ["DNP", "Modbus", "IEC61850"]
    assert dev.extra["communications"]["ipv4_address"] == "192.0.2.30"
    assert dev.extra["communications"]["network_mode"] == "FAILOVER"
    assert {"00:30:A7:01:09:2E", "00:30:A7:01:09:2F"} <= dev.related.mac
    assert dev.extra["ip_mac"] == "00:30:A7:01:09:2E"
    assert dev.extra["time_quality"]["last_update_source"] == "NONV CLK"
    assert dev.extra["time_quality"]["last_update"] == "2024-04-12T08:00:01"
    assert dev.extra["time_source"] == "OTHER"
    assert dev.extra["goose"]["receive"][0]["ied_name"] == "SEL_487E_1"
    assert {"SEL_351S_1", "SEL_487E_1"} <= dev.related.hosts
    assert not {"01:0C:CD:01:00:12", "01:0C:CD:01:00:10"} & dev.related.mac
    assert dev.extra["ser_element_names"][:3] == ["TRIP", "51P1T", "51G1T"]
    assert dev.extra["fast_meter_status_bits"][5] == "PWRUP"
    assert len(dev.extra["fast_meter_relay_word_bits"]) == 16
    assert dev.extra["compressed_status"]["RAM"] == "OK"
    assert dev.extra["active_settings_group"] == "1"
    # DATE_F from SHO G, used to parse the dates of the events
    assert dev.extra["date_format"] == "MDY"

    # Only what wasn't parsed is in extra.additional_command_outputs
    unparsed = dev.extra.get("additional_command_outputs", {})
    assert not {"ser", "his", "sta", "ver", "eth", "goose", "sho_g", "time_quality"} & set(
        unparsed
    )

    # The outputs are saved and hashed
    outputs = _file(dev, "additional-command-outputs.json")
    assert outputs.extra["transport"] == "telnet"
    data = json.loads(outputs.local_path.read_text())
    assert data["ver"]["command"] == "VER"
    assert data["ver"]["result"][0] == "Partnumber: 0351S7XHD3E5462"
    assert data["help"]["error"] == "Invalid Command"
    ver = _file(dev, "ver.txt")
    assert ver.extra["source"] == "command_output"
    assert ver.extra["transport"] == "telnet"
    assert ver.extra["commands"] == ["VER"]
    raw = ver.local_path.read_bytes()
    assert raw.startswith(b"VER\r\n\x02")
    assert ver.hash.sha256 == hashlib.sha256(raw).hexdigest().upper()
    assert ver.hash.sha256 in dev.related.hash
    assert _file(dev, "sho_g.txt").local_path.parent.name == "ascii_commands"


def test_pull_more_commands_id_when_not_verified(relay_server):
    # A pull without a scan: the FID and model aren't known yet (I3: iedName etc.)
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S))
    dev = _dev()

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)
    assert sent[:2] == ["ACC", "id"]
    assert dev.firmware.id == tr.FID_351S
    assert dev.description.model == "351S"
    # The model is known for the rest of the commands
    assert "SER" in sent


def test_chi_only_if_his_fails(relay_server):
    # HIS is answered with "Invalid Command", so CHI (which CAS lists) is used
    outputs = {k: v for k, v in tr.OUTPUTS_351S.items() if k != "HIS"}
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=outputs))
    dev = _dev("351S", tr.FID_351S)

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)
    assert sent.index("his") + 1 == sent.index("CHI")
    assert dev.extra["command_errors"]["his"] == "Invalid Command"
    history = [e for e in dev.event if e.dataset == "history"]
    assert len(history) == 1
    assert history[0].extra["source_datasets"] == ["CHI"]


def test_sho_settings_used_without_a_settings_file(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S))
    dev = _dev("351S", tr.FID_351S)
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    dev._runtime_options["sel"] = {"attempt_more_commands": True}

    # e.g. FTP and FILE SHOW aren't available
    assert SELRelay.pull_telnet(dev, pull_files=False) is True
    assert dev.extra["settings_source"] == "sho_commands"
    assert "=>>SHO G" in dev.logic.original
    assert "DATE_F" in dev.logic.original
    assert dev.extra["raw_rid"] == "FEEDER 1"
    assert dev.extra["raw_tid"] == "STATION A"

    # A settings file from a later pull method (e.g. FTP after Telnet) replaces them
    set_all = (Path(__file__).parent / "data_files" / "relay" / "sel-710_SET_ALL.TXT").read_text()
    assert SELRelay.parse_config(set_all, dev) is dev
    assert dev.logic.original == set_all
    assert "settings_source" not in dev.extra


def test_sho_settings_not_used_if_settings_were_pulled(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S))
    dev = _dev("351S", tr.FID_351S)
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    dev._runtime_options["sel"] = {"attempt_more_commands": True}
    dev.logic.original = "[INFO]\r\nRELAYTYPE=0351S\r\n"  # e.g. SET_ALL.TXT from FTP

    assert SELRelay.pull_telnet(dev, pull_files=False) is True
    assert "settings_source" not in dev.extra
    assert dev.logic.original.startswith("[INFO]")


def test_show_settings_option(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S))
    dev = _dev("351S", tr.FID_351S)
    dev._runtime_options["sel"] = {"show_settings": ["P 5"]}
    _, _, relay = _pull(server, dev)
    assert [c for c in _sent(relay) if c.startswith("SHO")] == ["SHO P 5"]

    dev = _dev("351S", tr.FID_351S, ident="127.0.0.2")
    dev._runtime_options["sel"] = {"show_settings": []}
    tn = _telnet(server)
    assert tn.elevate(1)
    SELRelay.pull_more_commands(dev, tn)
    tn.disconnect()
    assert not [c for c in _sent(server.relays[-1]) if c.startswith("SHO")]


# ---------------------------------------------------------------------------
# pull_more_commands(): 400 series, CSE, and the hardware configuration question
# ---------------------------------------------------------------------------


def test_pull_more_commands_421_uses_cse(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, outputs=tr.OUTPUTS_421))
    dev = _dev("421", tr.FID_421)

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)

    # STA, STA S, and STA A run at level 1, before 2AC
    assert sent[:7] == ["ACC", "HELP", "CAS", "sta", "sta s", "STA A", "2AC"]
    # CAS lists CSE, so the SER isn't read with SER (which has only 20 records)
    assert "CSE" in sent
    assert not [c for c in sent if c.upper().startswith("SER")]
    # HELP doesn't list GOO (a new command), so it isn't sent. The commands PEAT
    # ran before are sent even if HELP doesn't list them.
    assert "GOO" not in sent
    assert dev.extra["skipped_commands"]["goose"] == "HELP doesn't list it"
    for command in ("mac", "bre", "eve", "sum"):
        assert command in sent
    assert "mac" not in dev.extra["skipped_commands"]
    assert "CSE" in dev.extra["ascii_commands"]
    # Level 0 commands are tried anyway (HELP at level 1 may not list them)
    assert "SNS" in sent

    ser = sorted((e for e in dev.event if e.dataset == "ser"), key=lambda e: e.sequence)
    assert len(ser) == 4
    assert ser[-1].extra["element"] == "Power-up"
    assert ser[-1].type == {"start"}
    assert ser[-1].extra["source_datasets"] == ["CSE"]
    assert dev.extra["uptime_source"] == "ser_power_up"
    # From the relay's DATE and TIME, since CSE has no header with the time
    assert dev.uptime == timedelta(days=1, hours=8, minutes=31, seconds=9, milliseconds=996)

    assert dev.extra["status_warnings"] == ["IO_BRD1 Warning"]
    assert dev.extra["time_quality"]["time_source"] == "HIRIG"
    assert dev.extra["time_sync_source"] == "IRIG-B"
    assert dev.status == "enabled"


def test_cse_and_ser_records_are_not_duplicated(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, outputs=tr.OUTPUTS_421))
    dev = _dev("421", tr.FID_421)
    _pull(server, dev)
    assert len([e for e in dev.event if e.dataset == "ser"]) == 4

    # The same records, from the text SER report (e.g. SER.TXT)
    parse_and_process_events("\r\n".join(tr.SER_421), "SER.TXT", dev)
    ser = [e for e in dev.event if e.dataset == "ser"]
    assert len(ser) == 4
    assert all(e.extra["source_datasets"] == ["CSE", "SER.TXT"] for e in ser)


def test_cse_falls_back_to_ser_on_invalid_command(relay_server):
    outputs = {k: v for k, v in tr.OUTPUTS_421.items() if k != "CSE"}
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, outputs=outputs))
    dev = _dev("421", tr.FID_421)

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)
    assert sent.index("CSE") + 1 == sent.index("SER 1000")
    assert dev.extra["command_errors"]["cse"] == "Invalid Command"
    ser = [e for e in dev.event if e.dataset == "ser"]
    assert len(ser) == 4
    assert ser[0].extra["source_datasets"] == ["SER"]


def test_ser_1000_falls_back_to_ser(relay_server):
    outputs = {k: v for k, v in tr.OUTPUTS_421.items() if k not in ("CSE", "SER 1000")}
    outputs["SER"] = tr.SER_421
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, outputs=outputs))
    dev = _dev("421", tr.FID_421)

    _, _, relay = _pull(server, dev)
    sent = _sent(relay)
    assert sent.index("SER 1000") + 1 == sent.index("SER")
    assert len([e for e in dev.event if e.dataset == "ser"]) == 4


@pytest.fixture
def short_legacy_sleeps(mocker):
    # sel.legacy_ascii_timing sleeps up to 10 s after a command
    real_sleep = time.sleep
    mocker.patch.object(sel_ascii, "sleep", side_effect=lambda s: real_sleep(min(s, 0.3)))


def _legacy_421(server: TCPRelayServer) -> SELTelnet:
    tn = SELTelnet("127.0.0.1", server.port, timeout=2.0, legacy_timing=True)
    tn.model = "421"
    return tn


@pytest.mark.usefixtures("short_legacy_sleeps")
def test_ser_1000_with_legacy_timing_after_an_error(relay_server):
    # exec_read() doesn't record a response with legacy timing, so the error of
    # an earlier command (here CSE) isn't taken as the answer to SER 1000
    outputs = {k: v for k, v in tr.OUTPUTS_421.items() if k != "CSE"}
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, level="2", outputs=outputs))
    tn = _legacy_421(server)
    assert tn.run_read_command("CSE").error == "Invalid Command"
    result = tn.show_ser()
    tn.disconnect()
    assert _sent(server.relays[0])[:2] == ["CSE", "SER 1000"]
    assert "SER" not in _sent(server.relays[0])
    assert any("Power-up" in line for line in result)


@pytest.mark.usefixtures("short_legacy_sleeps")
def test_ser_1000_falls_back_to_ser_with_legacy_timing(relay_server):
    # SER 1000 is rejected after a command that worked: the error is read from
    # the output, and SER is used
    outputs = {k: v for k, v in tr.OUTPUTS_421.items() if k not in ("CSE", "SER 1000")}
    outputs["SER"] = tr.SER_421
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, level="2", outputs=outputs))
    tn = _legacy_421(server)
    assert not tn.run_read_command("TIM Q").error
    result = tn.show_ser()
    tn.disconnect()
    assert _sent(server.relays[0])[:3] == ["TIM Q", "SER 1000", "SER"]
    assert "Invalid Command" not in result
    assert any("Power-up" in line for line in result)
    assert tn.is_unsupported("SER 1000")


@pytest.mark.usefixtures("short_legacy_sleeps")
def test_cse_falls_back_to_ser_with_legacy_timing(relay_server):
    outputs = {k: v for k, v in tr.OUTPUTS_421.items() if k != "CSE"}
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, level="2", outputs=outputs))
    tn = _legacy_421(server)
    collector = MoreCommands(_dev("421", tr.FID_421), tn, show_settings=[])
    collector.cas_commands = {"CSE": {"access_level": 1}}
    collector._run_events("cse", "ser")
    tn.disconnect()
    assert _sent(server.relays[0])[:2] == ["CSE", "SER 1000"]
    assert "SER" not in _sent(server.relays[0])
    assert collector.errors["cse"] == "Invalid Command"
    assert any("Power-up" in line for line in collector.outputs["ser"]["result"])


def test_400_series_sta_question_is_never_confirmed(relay_server, mocker):
    # The serial port was left at level 2, so STA asks "Accept new hardware
    # configuration (Y/N)?" (SEL-421 IM 20130627, Table 9.125). PEAT answers N.
    mocker.patch.object(SELAscii, "QUESTION_SETTLE", 0.1)
    server = relay_server(
        lambda: FakeSELRelay(fid=tr.FID_421, level="2", sta_question=True, outputs=tr.OUTPUTS_421)
    )
    dev = _dev("421", tr.FID_421)
    tn = _telnet(server)
    assert SELRelay.pull_more_commands(dev, tn) is True
    tn.disconnect()
    relay = server.relays[0]
    assert relay.answers
    assert all(answer == "N" for _, answer in relay.answers)
    assert "Y" not in _sent(relay)
    assert dev.extra["command_errors"]["sta"].startswith("Unexpected question")
    # The other commands still run
    assert "CSE" in _sent(relay)


def test_pull_more_commands_751a(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_751A, outputs=tr.OUTPUTS_751A))
    dev = _dev("751A", tr.FID_751A)

    result, _, relay = _pull(server, dev)
    assert result is True
    sent = _sent(relay)
    assert sent.index("2AC") < sent.index("sta")  # Only the 400 series runs STA first
    assert "STA A" not in sent
    assert dev.extra["selogic_usage"]["usage_percent"]["Global"] == 81.0
    assert dev.extra["port_1_mac"] == "00:30:A7:00:75:6A"
    assert dev.extra["self_tests"]["CID_FILE"] == "OK"


def test_pull_more_commands_2032(relay_server):
    outputs = {
        "SER GLOBAL 100": ["No SER data"],
        "DNP": ["DNP map"],
        "WHO": ["Port 1: SEL-351S"],
        "STA": ["FIDSEL-2032-R115", "Port 1 OK"],
        "CAR 17": ["Card 17"],
    }
    server = relay_server(lambda: FakeSELRelay(fid="SEL-2032-R115-V1", outputs=outputs))
    dev = _dev("2032", "SEL-2032-R115-V1-Z003001-D20151028")

    result, _, relay = _pull(server, dev)
    assert result is True
    # The commands PEAT ran before on the SEL-2032, without level 2 or discovery
    assert _sent(relay)[:-2] == [
        "ACC",
        "SER GLOBAL 100",
        "sta",
        "DNPMAP",
        "WHO",
        "STATUS",
        "CARD 17",
        "CARD 18",
    ]
    assert dev.extra["additional_command_outputs"]["who"]["result"] == ["Port 1: SEL-351S"]


def test_connection_lost_stops_the_commands(relay_server):
    server = relay_server(
        lambda: FakeSELRelay(fid=tr.FID_351S, outputs=tr.OUTPUTS_351S, close_after="VER")
    )
    dev = _dev("351S", tr.FID_351S)

    tn = _telnet(server)
    assert tn.elevate(1)
    assert SELRelay.pull_more_commands(dev, tn) is True  # Some commands worked
    tn.disconnect()
    # PEAT doesn't connect again for the other commands
    assert len(server.relays) == 1
    sent = _sent(server.relays[0])
    assert sent[-1] == "VER"


def test_more_commands_collector_unknown_family(relay_server):
    # A model without a known family (e.g. SEL-2411) gets the relay commands
    server = relay_server(lambda: FakeSELRelay(fid="SEL-2411-R308", outputs={}))
    dev = _dev("2411", "SEL-2411-R308-V0-Z005005-D20110902")
    tn = _telnet(server)
    assert tn.elevate(1)
    collector = MoreCommands(dev, tn, show_settings=[])
    collector.run()
    tn.disconnect()
    sent = _sent(server.relays[0])
    assert "SER" in sent
    assert "VER" in sent
    assert "STA A" not in sent
    assert collector.skipped["sta_all"] == "not sent to the unknown family"


# ---------------------------------------------------------------------------
# Telnet and serial
# ---------------------------------------------------------------------------


def test_same_commands_on_telnet_and_serial(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=tr.FID_421, outputs=tr.OUTPUTS_421))
    _pull(server, _dev("421", tr.FID_421))
    telnet_sent = _sent(server.relays[0])
    assert telnet_sent[-2:] == ["quit", "exit"]  # When disconnecting
    telnet_sent = telnet_sent[:-2]
    SELAscii.forget_unsupported_commands()

    relay = FakeSELRelay(fid=tr.FID_421, outputs=tr.OUTPUTS_421)
    port = FakeSerialPort(relay)
    ser = SELSerial("/dev/ttyFAKE0", timeout=2.0)
    ser.comm = port
    assert ser.elevate(1)
    dev = _dev("421", tr.FID_421, ident="192.0.2.90")
    assert SELRelay.pull_more_commands(dev, ser) is True
    assert _sent(relay) == telnet_sent
    assert _file(dev, "additional-command-outputs.json").extra["transport"] == "serial"


def test_pull_serial_runs_the_commands_before_the_files(mocker):
    calls = []
    relay = FakeSELRelay(fid=tr.FID_421, outputs=tr.OUTPUTS_421)
    port = FakeSerialPort(relay)
    mocker.patch.object(SELSerial, "test_connection", return_value=True)
    mocker.patch.object(SELSerial, "comm", new_callable=mocker.PropertyMock, return_value=port)
    mocker.patch.object(
        SELRelay, "pull_more_commands", side_effect=lambda **_: calls.append("commands") or True
    )
    mocker.patch.object(SELRelay, "pull_configs", side_effect=lambda *_: calls.append("files"))

    dev = datastore.get("/dev/ttyFAKE1", "serial_port")
    dev._runtime_options["serial"] = {"baudrate": 9600}
    dev._runtime_options["sel"] = {"attempt_more_commands": True}
    SELRelay.pull_serial(dev)
    # On a SEL-400, FILE READ of SER.TXT clears the SER records viewed from the port
    assert calls == ["commands", "files"]


def test_run_read_command_returns_the_response(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="1", outputs={"TIM Q": tr.TIME_Q_421}))
    tn = _telnet(server)
    response = tn.run_read_command("TIM Q")
    assert isinstance(response, SELResponse)
    assert response.complete
    assert "Time Source: HIRIG" in response.lines
    assert tn.responses[-1] is response
    tn.disconnect()
