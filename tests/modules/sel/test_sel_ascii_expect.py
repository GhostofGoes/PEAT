"""
Tests for waiting for SEL ASCII prompts (SELAscii, SELTelnet, and SELSerial),
against the scripted relay in fake_sel_relay.py. No hardware is needed.

The prompt and dialog formats are from public SEL instruction manuals
(SEL-351S IM 20171023 Section 10, SEL-421 IM 20130627 Table 4.3); the data is synthetic.
"""

import json
import socket
import threading
import time

import pytest

from peat import SELRelay, config, datastore
from peat.modules.sel import sel_ascii
from peat.modules.sel.sel_ascii import (
    FRAMED_PROMPT_RE,
    LEVEL_RANKS,
    PROMPT_LEVELS,
    TRAILING_PROMPT_RE,
    UNFRAMED_PROMPT_RE,
    SELAscii,
    SELResponse,
    SELSessionHalted,
    clean_lines,
)
from peat.modules.sel.sel_serial import SELSerial
from peat.modules.sel.sel_telnet import SELTelnet
from peat.protocols.expect import Expecter

from .fake_sel_relay import (
    FID_451,
    FID_751,
    FakeSELRelay,
    FakeSerialPort,
    TCPRelayServer,
)

SET_1 = '[INFO]\r\nRELAYTYPE=0351S\r\n[1]\r\nRID,"FEEDER 1"\r\nTID,"STATION A"\r\n' + "".join(
    f'X{i:03d},"{i}"\r\n' for i in range(150)
)


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


def _telnet(server: TCPRelayServer, **kwargs) -> SELTelnet:
    return SELTelnet("127.0.0.1", server.port, timeout=2.0, **kwargs)


# ---------------------------------------------------------------------------
# Prompts and access levels
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("prompt", "level", "rank"),
    [
        ("=", "0", 0),
        ("=>", "1", 1),
        ("==>", "B", 1),
        ("P=>", "P", 1),
        ("A=>", "A", 1),
        ("O=>", "O", 1),
        ("E=>", "E", 1),
        ("=>>", "2", 2),
        ("==>>", "C", 3),
        ("*", "0", 0),
        ("*>", "1", 1),
        ("*>>", "2", 2),
        ("#>", "1", 1),
        ("#>>", "2", 2),
    ],
)
def test_prompt_levels(prompt, level, rank):
    framed = FRAMED_PROMPT_RE.search(b"\x03\x02\r\n" + prompt.encode() + b"\x03")
    assert framed.group("prompt").decode() == prompt
    unframed = UNFRAMED_PROMPT_RE.search(b"output\r\n" + prompt.encode())
    assert unframed.group("prompt").decode() == prompt

    assert PROMPT_LEVELS[prompt] == level
    assert LEVEL_RANKS[level] == rank

    tn = SELTelnet("192.0.2.1")
    assert tn._set_level_from_prompt(prompt)
    assert tn.access_level == level
    assert tn.priv_level == rank


def test_calibration_prompt_regression():
    # The old serial code checked "=>" before "=>>", so "==>>" (level C) was level 2
    tn = SELTelnet("192.0.2.1")
    tn._note_prompt_in_text("Level C\r\n\x02\r\n==>>\x03")
    assert tn.access_level == "C"
    assert tn.priv_level == 3
    tn._note_prompt_in_text("\r\n==>")
    assert tn.access_level == "B"
    assert tn.priv_level == 1


@pytest.mark.parametrize("prompt", [b"*", b"*>", b"*>>", b"=>>"])
def test_prompt_framed_with_a_space(prompt):
    # SEL-2032 IM 20120126, Figure 8.1: "<ETX><STX> <PROMPT><ETX>"
    data = b"\x02\r\nOUTPUT\r\n\x03\x02 " + prompt + b"\x03"
    assert FRAMED_PROMPT_RE.search(data).group("prompt") == prompt
    assert TRAILING_PROMPT_RE.search(data).group("prompt") == prompt


def test_session_with_prompts_framed_with_a_space(relay_server):
    server = relay_server(lambda: FakeSELRelay(prompt_prefix=b" "))
    tn = _telnet(server)
    assert tn.get_id()["FID"]
    assert tn.last_response.complete
    assert tn.elevate(2) is True
    assert tn.access_level == "2"
    tn.disconnect()


def test_unframed_prompt_rules():
    # A prompt right after a STX is the start of a framed prompt (wait for the ETX)
    assert not UNFRAMED_PROMPT_RE.search(b"\x02\r\n=>")
    assert not UNFRAMED_PROMPT_RE.search(b"\x02=>")
    # Only at the start of a line, at the end of the data
    assert not UNFRAMED_PROMPT_RE.search(b"RID := FEEDER =>")
    assert not UNFRAMED_PROMPT_RE.search(b"\r\n=> more")
    assert UNFRAMED_PROMPT_RE.search(b"=>").group("prompt") == b"=>"
    assert UNFRAMED_PROMPT_RE.search(b"\r\n\r\n=> ").group("prompt") == b"=>"
    assert sel_ascii._in_open_message(b"x\x02abc\r\n=>", 9)
    assert not sel_ascii._in_open_message(b"\x02abc\x03\r\n=>", 9)


def test_clean_lines():
    assert clean_lines('id\r\n\x02\r\n"FID=X","0123"\r\n\x03\x02\r\n=>\x03') == [
        "id",
        '"FID=X","0123"',
        "=>",
    ]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def test_get_id(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=FID_451))
    tn = _telnet(server)

    started = time.monotonic()
    info = tn.get_id()
    # The old code always waited 5 seconds
    assert time.monotonic() - started < 2.0
    assert info["FID"] == FID_451
    assert tn.access_level == "0"
    assert tn.model == "451"
    assert tn.last_response.complete
    assert not tn.last_response.timed_out
    tn.disconnect()


def test_run_command_response(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="1"))
    tn = _telnet(server)

    response = tn.run_command("STA")
    assert isinstance(response, SELResponse)
    assert response.prompt == "=>"
    assert response.level == "1"
    assert response.lines == [f"FID={FakeSELRelay().fid}  CID=59A0", "Relay Enabled"]
    assert response.raw.startswith("STA\r\n\x02")
    assert not response.error

    invalid = tn.run_command("XYZ")
    assert invalid.error == "Invalid Command"
    assert invalid.complete
    assert invalid.lines == ["Invalid Command"]
    tn.disconnect()


def test_exec_read_compatibility(relay_server):
    server = relay_server(lambda: FakeSELRelay(level="1"))
    tn = _telnet(server)
    assert tn.exec_read("dat") == ["02/02/09"]
    raw = tn.exec_read("tim", return_lines=False, added_delay=2.0)
    assert raw.startswith("tim")
    assert "08:31:10" in raw
    assert tn.get_device_time().year == 2009
    tn.disconnect()


def test_no_prompt_times_out(mocker):
    # A device that answers, but never with a SEL prompt (e.g. not a SEL device)
    tn = SELTelnet("192.0.2.2", timeout=0.3)
    mocker.patch.object(tn, "_write_raw")
    mocker.patch.object(tn, "_read_available", return_value=b"")
    chunks = [b"Welcome to something else\r\n"]
    expecter = Expecter(lambda wait: chunks.pop() if chunks else time.sleep(wait) or b"")
    mocker.patch.object(tn, "_expect_raw", side_effect=expecter.expect)

    started = time.monotonic()
    response = tn.run_command("id")
    # Without output, PEAT stops waiting after the timeout of the connection
    assert time.monotonic() - started < 2.0
    assert response.timed_out
    assert not response.complete
    assert response.lines == ["Welcome to something else"]
    assert tn.access_level == ""


def test_streaming_device_is_not_read_for_long():
    # A device that keeps sending data, but never a SEL prompt (e.g. a gateway
    # that streams readings): the "id" wait during a scan is bounded by the old
    # fixed delay, not by the idle timeout of long commands
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()

    def serve():
        conn, _ = listener.accept()
        while not stop.is_set():
            try:
                conn.sendall(b"temp=21.5\r\n")
            except OSError:
                break
            time.sleep(0.1)
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    tn = SELTelnet("127.0.0.1", listener.getsockname()[1], timeout=0.5)

    started = time.monotonic()
    raw = tn.exec_read("id", return_lines=False, added_delay=1.0)
    assert time.monotonic() - started < 3.0
    assert "temp=21.5" in raw
    assert tn.last_response.timed_out
    stop.set()
    tn.disconnect()
    thread.join(timeout=5)
    listener.close()


def test_list_files(relay_server):
    files = {"CFG.TXT": "[INFO]\r\n", "SETTINGS SET_1.TXT": SET_1, "SETTINGS SET_P1.TXT": "x"}
    server = relay_server(lambda: FakeSELRelay(files=files))
    tn = _telnet(server)

    started = time.monotonic()
    assert tn.list_files() == ["CFG.TXT", "SETTINGS"]
    assert tn.list_files("SETTINGS") == ["SET_1.TXT", "SET_P1.TXT"]
    assert tn.list_files("EVENTS") == []
    # The old code slept 10 seconds per directory
    assert time.monotonic() - started < 3.0
    assert tn.priv_level == 1  # Elevated automatically
    tn.disconnect()


def test_file_show_one_byte_chunks(relay_server):
    # A slow link: the file arrives one byte at a time, and stalls for longer
    # than the old read delay in the middle. The old code stopped at the
    # first empty read and returned a truncated file.
    server = relay_server(
        lambda: FakeSELRelay(level="1", files={"SETTINGS SET_1.TXT": SET_1}),
        chunk_size=1,
        pause_at=(b'X010,"10"', 0.6),
    )
    tn = _telnet(server)
    assert tn.download_binary("SETTINGS SET_1.TXT", save_to_file=False) == SET_1
    tn.disconnect()


def test_file_show_truncated_with_legacy_timing(relay_server, mocker):
    # The same stall with the old timing cuts the file off (for comparison)
    mocker.patch.object(SELTelnet, "can_download_files", return_value=True)
    server = relay_server(
        lambda: FakeSELRelay(level="1", files={"SETTINGS SET_1.TXT": SET_1}),
        pause_at=(b'X010,"10"', 0.6),
    )
    tn = _telnet(server, legacy_timing=True)
    tn.priv_level = 1
    data = tn.download_binary("SETTINGS SET_1.TXT", save_to_file=False)
    assert data is not None
    assert len(data) < len(SET_1)
    tn.disconnect()


def test_prompt_inside_file_is_not_the_end(relay_server, mocker):
    # Lines that look like prompts inside the file (an open STX message) aren't
    # the prompt, even if the transfer stalls right after one
    content = "line 1\r\n=>\r\n=\r\nlast line\r\n"
    mocker.patch.object(SELAscii, "PROMPT_SETTLE", 0.05)
    server = relay_server(
        lambda: FakeSELRelay(level="1", files={"NOTES.TXT": content}),
        pause_at=(b"\r\n=>", 0.3),
    )
    tn = _telnet(server)
    tn.telnet_download_capable = True
    assert tn.show_file("NOTES.TXT") == content
    tn.disconnect()


@pytest.mark.parametrize("frame_errors", [True, False])
def test_file_show_errors(relay_server, frame_errors):
    # The fake relay frames error messages with STX/ETX by default, like a file
    # (SEL-2032 IM 20120126, Figure 8.1). The error isn't returned as the file.
    server = relay_server(
        lambda: FakeSELRelay(level="1", files={"A.TXT": "a"}, frame_errors=frame_errors)
    )
    tn = _telnet(server)
    assert tn.can_download_files() is True
    assert tn.show_file("MISSING.TXT") is None
    assert tn.last_response.error == "Invalid File Name"
    assert tn.download_binary("MISSING.TXT") is None
    assert not list(config.DEVICE_DIR.rglob("MISSING.TXT"))
    assert tn.show_file("A.TXT") == "a"
    tn.disconnect()


def test_file_show_error_like_text_in_a_file(relay_server):
    # A file with more than one line is a file, even if it starts like an error
    content = "Invalid entries:\r\nX001,1\r\n"
    server = relay_server(lambda: FakeSELRelay(level="1", files={"NOTES.TXT": content}))
    tn = _telnet(server)
    tn.telnet_download_capable = True
    assert tn.show_file("NOTES.TXT") == content
    tn.disconnect()


def test_echo_only_output_no_index_error(mocker):
    # Every line is the echo or the prompt (IndexError in the old download loops)
    tn = SELTelnet("192.0.2.3", legacy_timing=True)
    tn.priv_level = 1
    tn.telnet_download_capable = True
    mocker.patch.object(tn, "write")
    mocker.patch.object(tn, "read", side_effect=["", "fil show X.TXT\r\n=>", ""])
    assert tn.download_binary("X.TXT", save_to_file=False) == ""

    ser = SELSerial("/dev/ttyFAKE1", legacy_timing=True)
    ser.priv_level = 1
    ser._supports_show = True
    mocker.patch.object(ser, "write")
    mocker.patch.object(ser, "read", side_effect=["", "", "fil show X.TXT\r\n=>", ""])
    assert ser.download_binary("X.TXT") == ""


def test_can_download_files_rechecks_after_no_response(mocker):
    tn = SELTelnet("192.0.2.4")
    tn.priv_level = 1
    run = mocker.patch.object(
        tn, "run_command", return_value=SELResponse(command="fil show", timed_out=True)
    )
    assert tn.can_download_files() is False
    assert tn.telnet_download_capable is None  # Not remembered
    run.return_value = SELResponse(
        command="fil show", prompt="=>", lines=["Command requires a filename"]
    )
    assert tn.can_download_files() is True
    assert tn.telnet_download_capable is True


def test_unframed_prompts(relay_server, mocker):
    mocker.patch.object(SELAscii, "PROMPT_SETTLE", 0.2)
    server = relay_server(
        lambda: FakeSELRelay(framed_prompts=False),
        chunk_size=1,
        chunk_delay=0.002,
    )
    tn = _telnet(server)
    assert tn.get_id()["FID"]
    assert tn.elevate(2)
    # "=>>" arrives one byte at a time: "=>" isn't taken as the prompt
    assert tn.access_level == "2"
    tn.disconnect()


def test_legacy_timing_uses_fixed_delays(relay_server, mocker):
    sleep = mocker.patch.object(sel_ascii, "sleep")
    server = relay_server(lambda: FakeSELRelay(level="1"))
    tn = _telnet(server, legacy_timing=True)
    info = tn.get_id()
    assert info["FID"]
    assert mocker.call(5.0) in sleep.call_args_list
    tn.disconnect()

    sleep.reset_mock()
    tn = _telnet(server)
    assert tn.get_id()["FID"]
    assert sleep.call_count == 0
    tn.disconnect()


# ---------------------------------------------------------------------------
# Logins
# ---------------------------------------------------------------------------


def test_elevate_with_default_passwords(relay_server):
    server = relay_server()
    tn = _telnet(server)
    assert tn.elevate(2) is True
    assert tn.access_level == "2"
    assert tn.successful_usernames == {"acc", "2ac"}
    relay = server.relays[0]
    assert relay.password_attempts == {"acc": ["OTTER"], "2ac": ["TAIL"]}
    assert tn.elevate(1) is True  # Already above level 1
    tn.disconnect()
    assert relay.lines[-2:] == [b"quit", b"exit"]


def test_elevate_to_calibration(relay_server):
    server = relay_server()
    tn = _telnet(server)
    assert tn.elevate(3) is True
    assert tn.access_level == "C"
    assert tn.priv_level == 3
    tn.disconnect()


def test_wrong_password_is_tried_once_and_cancelled(relay_server):
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "Non-Default1"}))
    tn = _telnet(server)

    assert tn.elevate(1) is False
    relay = server.relays[0]
    # One password, then CAN, so the relay doesn't count more wrong passwords
    assert relay.password_attempts == {"acc": ["OTTER"]}
    assert relay.cancels == 1
    assert relay.lockouts == 0
    assert tn.access_level == "0"

    # Not tried again on the same connection
    assert tn.elevate(1) is False
    assert relay.password_attempts == {"acc": ["OTTER"]}
    tn.disconnect()

    # The default that failed isn't tried again on a new connection either
    tn = _telnet(server)
    assert tn.elevate(1) is False
    assert b"ACC" not in server.relays[1].lines
    tn.disconnect()

    # The configured password is used
    tn = _telnet(server)
    assert tn.elevate(1, {"acc": "Non-Default1"}) is True
    assert server.relays[2].password_attempts == {"acc": ["Non-Default1"]}
    # The configured creds are used for automatic elevation
    assert tn.creds == {"acc": "Non-Default1"}
    tn.disconnect()


def test_no_answer_to_password_is_cancelled(relay_server):
    class SilentRelay(FakeSELRelay):
        def _password(self, text):
            # Never answers the password
            self.password_attempts.setdefault("acc", []).append(text)

    server = relay_server(SilentRelay)
    tn = _telnet(server)
    tn.timeout = 0.3
    assert tn.elevate(1) is False
    relay = server.relays[0]
    assert relay.password_attempts == {"acc": ["OTTER"]}
    # CAN ends the password dialog, so QUIT isn't taken as another password
    assert relay.cancels == 1
    tn.disconnect()
    assert relay.lines[-2:] == [b"quit", b"exit"]
    assert relay.password_attempts == {"acc": ["OTTER"]}


def test_nothing_is_sent_after_can_is_ignored(relay_server):
    # The relay keeps asking for the password after CAN: anything sent now would
    # be another wrong password (3 in a row: BADPASS and a 30 s lockout)
    server = relay_server(
        lambda: FakeSELRelay(passwords={"acc": "OTTER", "2ac": "Other-2"}, ignore_can=True)
    )
    tn = _telnet(server)
    tn.timeout = 0.3
    assert tn.elevate(1) is True
    assert tn.elevate(2) is False
    assert "CAN" in tn.halted
    relay = server.relays[0]
    assert relay.lines[-1] == b"TAIL"
    assert relay.cancels == 1

    with pytest.raises(SELSessionHalted):
        tn.run_command("ser", long=True)
    with pytest.raises(SELSessionHalted):
        tn.write("his")
    assert tn.elevate(2) is False
    with pytest.raises(SELSessionHalted):
        tn.get_sta()

    tn.disconnect()
    time.sleep(0.1)
    # Not even QUIT or EXIT
    assert relay.lines[-1] == b"TAIL"
    assert relay.password_attempts == {"acc": ["OTTER"], "2ac": ["TAIL"]}
    assert relay.lockouts == 0
    # A new Telnet connection is a new session on the relay
    assert tn.halted == ""


def test_pull_more_commands_stops_when_halted(relay_server):
    server = relay_server(
        lambda: FakeSELRelay(passwords={"acc": "OTTER", "2ac": "Other-2"}, ignore_can=True)
    )
    dev = datastore.get("127.0.0.1", "ip")
    dev.description.model = "351S"
    tn = _telnet(server)
    tn.timeout = 0.3

    assert SELRelay.pull_more_commands(dev, tn) is False
    assert tn.halted
    assert SELRelay.pull_configs(dev, tn) is False
    tn.disconnect()
    time.sleep(0.1)
    relay = server.relays[0]
    assert relay.lines[-1] == b"TAIL"
    assert not {b"ser", b"his", b"sta", b"date", b"fil dir"} & set(relay.lines)


def test_serial_halt_is_kept_after_disconnect():
    # The relay's serial port keeps its state (e.g. still asking for a password)
    relay = FakeSELRelay(passwords={"acc": "Other-1"}, ignore_can=True)
    ser, port = _serial(relay)
    ser.timeout = 0.3
    assert ser.elevate(1) is False
    assert ser.halted
    written = port.written
    assert written.endswith(b"\x18")

    ser.disconnect()
    assert ser.halted
    with pytest.raises(SELSessionHalted):
        ser.run_command("id")
    assert port.written == written


def test_selboot_prompt_halts_the_session(mocker):
    tn = SELTelnet("192.0.2.5")
    write = mocker.patch.object(tn, "_write_raw")
    tn._note_prompt_in_text("SELBOOT\r\n!>")
    assert tn.access_level == "SELBOOT"
    assert "SELBOOT" in tn.halted
    with pytest.raises(SELSessionHalted):
        tn.run_command("id")
    assert tn.elevate(1) is False
    write.assert_not_called()


def test_unexpected_question_is_answered_no(relay_server, mocker):
    # STA at level 2 on a SEL-400 after a board change (SEL-421 IM 20130627,
    # Table 9.125). Before, the next command was taken as the answer.
    mocker.patch.object(SELAscii, "QUESTION_SETTLE", 0.1)
    server = relay_server(lambda: FakeSELRelay(level="2", sta_question=True))
    tn = _telnet(server)

    response = tn.run_command("sta", long=True)
    assert response.error == "Unexpected question: Accept new hardware configuration (Y/N)?"
    assert not response.complete
    assert not tn.halted
    relay = server.relays[0]
    assert relay.answers == [("STA", "N")]

    assert tn.run_command("dat").lines == ["02/02/09"]
    assert relay.answers == [("STA", "N")]
    assert b"Y" not in relay.lines
    tn.disconnect()


def test_question_inside_a_file_is_not_a_question(relay_server, mocker):
    mocker.patch.object(SELAscii, "QUESTION_SETTLE", 0.05)
    content = "Apply settings (Y/N)?\r\nlast line\r\n"
    server = relay_server(
        lambda: FakeSELRelay(level="1", files={"NOTES.TXT": content}),
        pause_at=(b"(Y/N)?", 0.3),
    )
    tn = _telnet(server)
    tn.telnet_download_capable = True
    assert tn.show_file("NOTES.TXT") == content
    assert server.relays[0].answers == []
    tn.disconnect()


def test_forget_passwords(relay_server):
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "Non-Default1"}))
    tn = _telnet(server)
    assert tn.elevate(1) is False
    tn.disconnect()
    assert SELAscii._failed_passwords == {("127.0.0.1", "acc"): {"OTTER"}}

    SELAscii.forget_passwords("192.0.2.99")  # Another device
    assert SELAscii._failed_passwords
    dev = datastore.get("127.0.0.1", "ip")
    SELRelay._forget_ascii_passwords(dev)
    assert SELAscii._failed_passwords == {}

    # Tried again on the next connection (e.g. the password was fixed on the device)
    tn = _telnet(server)
    assert tn.elevate(1) is False
    assert server.relays[1].password_attempts == {"acc": ["OTTER"]}
    tn.disconnect()


def test_no_password_needed(relay_server):
    # E.g. the access jumper is installed: the relay doesn't ask for the password
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": None, "2ac": None}))
    tn = _telnet(server)
    assert tn.elevate(2) is True
    assert server.relays[0].password_attempts == {}
    tn.disconnect()


def test_maxacc_limits_2ac(relay_server):
    server = relay_server(lambda: FakeSELRelay(maxacc="1"))
    tn = _telnet(server)
    assert tn.elevate(2) is False
    assert tn.access_level == "1"
    assert "2ac" not in server.relays[0].password_attempts
    tn.disconnect()


def test_level_is_checked_before_elevating(relay_server):
    # E.g. a serial port that is still at level 2 from a previous session
    server = relay_server(lambda: FakeSELRelay(level="2"))
    tn = _telnet(server)
    assert tn.elevate(1) is True
    assert tn.access_level == "2"
    assert server.relays[0].password_attempts == {}
    tn.disconnect()


def test_ensure_priv_uses_configured_creds(relay_server):
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "Pw-1", "2ac": "Pw-2"}))
    tn = _telnet(server)
    assert tn.elevate(1, {"acc": "Pw-1", "2ac": "Pw-2"})
    tn._ensure_priv("test", level=2)
    assert tn.access_level == "2"
    tn.disconnect()


def test_passwords_are_redacted(relay_server, tmp_path, mocker):
    mocker.patch.dict(config["CONFIG"], {"LOG_DIR": tmp_path / "logs", "OUT_DIR": tmp_path})
    (tmp_path / "logs").mkdir()
    server = relay_server(
        lambda: FakeSELRelay(passwords={"acc": "Secret-77"}, echo_passwords=True)
    )

    with _telnet(server) as tn:
        assert tn.elevate(1, {"acc": "Secret-77"})
        assert b"<redacted>\r\n" in tn.all_writes
        assert not any(b"Secret-77" in w for w in tn.all_writes)
        # The relay echoed the password, it's redacted in the recorded output
        assert not any("Secret-77" in o for o in tn.all_output)
        assert not any(b"Secret-77" in o for o in tn.raw_output)
        assert not any("Secret-77" in o for o in tn.comm.all_output)

    log_files = list((tmp_path / "logs").glob("selascii-protocol-data_*.json"))
    assert log_files
    text = log_files[0].read_text()
    assert "Secret-77" not in text
    assert "<redacted>" in text
    assert json.loads(text)[0]["final_access_level"] == "1"

    raw = list((tmp_path / "devices").rglob("raw-telnet-output.json"))
    assert raw
    assert "Secret-77" not in raw[0].read_text()


def test_default_passwords_are_not_redacted_from_output(relay_server):
    # Default passwords are public, and short (e.g. "TAIL" is in "DETAIL")
    server = relay_server()
    tn = _telnet(server)
    assert tn.elevate(1)
    assert b"<redacted>\r\n" in tn.all_writes
    assert tn._secrets == set()
    tn.disconnect()


# ---------------------------------------------------------------------------
# Verify and pull (SELRelay)
# ---------------------------------------------------------------------------


def test_verify_telnet_with_exit_info(relay_server):
    server = relay_server(lambda: FakeSELRelay(fid=FID_751))
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}

    assert SELRelay._verify_telnet(dev) is True
    assert dev.firmware.id == FID_751
    assert dev.description.model == "751"
    # From the output of "quit"
    assert dev.extra["RID"] == "FEEDER 1"
    assert dev.extra["TID"] == "STATION A"
    assert server.relays[0].lines == [b"id", b"quit", b"exit"]


def test_verify_telnet_not_a_sel_device():
    # A Telnet server that never answers (e.g. another kind of device, during a scan)
    received = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve():
        conn, _ = listener.accept()
        conn.settimeout(10)
        try:
            while data := conn.recv(100):
                received.append(data)
        except OSError:
            pass
        conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": listener.getsockname()[1], "timeout": 1.0}

    started = time.monotonic()
    assert SELRelay._verify_telnet(dev) is False
    # The ID wait is the same as the old fixed delay (5 s), and PEAT doesn't
    # wait for prompts after QUIT and EXIT
    assert time.monotonic() - started < 7.0
    thread.join(timeout=5)
    listener.close()
    assert b"".join(received) == b"id\r\nquit\r\nexit\r\n"


def test_pull_telnet_uses_configured_creds(relay_server, mocker):
    server = relay_server(lambda: FakeSELRelay(passwords={"acc": "Cfg-Pass1"}))
    mocker.patch.dict(datastore.global_options, {"sel": {"creds": {"acc": "Cfg-Pass1"}}})
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}

    assert SELRelay.pull_telnet(dev, pull_files=False) is True
    assert server.relays[0].password_attempts == {"acc": ["Cfg-Pass1"]}
    assert "acc" in dev.related.user


def test_legacy_timing_option(relay_server):
    server = relay_server()
    dev = datastore.get("127.0.0.1", "ip")
    dev._runtime_options["telnet"] = {"port": server.port, "timeout": 2.0}
    dev._runtime_options["sel"] = {"legacy_ascii_timing": True, "ascii_idle_timeout": 7.0}
    assert SELRelay._ascii_options(dev) == {"legacy_timing": True, "idle_timeout": 7.0}


# ---------------------------------------------------------------------------
# Serial
# ---------------------------------------------------------------------------


def _serial(relay: FakeSELRelay, **kwargs) -> tuple[SELSerial, FakeSerialPort]:
    port = FakeSerialPort(relay, **kwargs)
    ser = SELSerial("/dev/ttyFAKE0", timeout=2.0)
    ser.comm = port
    return ser, port


def test_serial_session():
    relay = FakeSELRelay(fid=FID_751, files={"SET_1.TXT": SET_1})
    ser, port = _serial(relay, chunk_size=16, chunk_delay=0.001)

    assert ser.get_id()["FID"] == FID_751
    assert ser.elevate(1)
    assert ser.supports_show is True
    assert ser.download_binary("SET_1.TXT") == SET_1

    ser.disconnect()
    # QUIT before closing, since the relay keeps the access level on serial
    assert relay.lines[-1] == b"quit"
    assert relay.level == "0"
    assert ser.priv_level == 0
    assert ser.access_level == ""
    assert not port.is_open


def test_serial_keeps_level_between_sessions():
    relay = FakeSELRelay(level="2")
    ser, _ = _serial(relay)
    assert ser.get_id()["FID"]
    # The prompt shows the level the port was left at
    assert ser.access_level == "2"
    assert ser.priv_level == 2


def test_serial_flow_control_removed():
    relay = FakeSELRelay(level="1")
    ser, _ = _serial(relay)
    original = relay.send
    relay.send = lambda data: original(data.replace(b"\r\n", b"\x13\r\n\x11"))
    response = ser.run_command("dat")
    assert response.lines == ["02/02/09"]
    assert "\x11" not in response.raw
    assert "\x13" not in response.raw


def test_serial_wrong_password():
    relay = FakeSELRelay(passwords={"acc": "Other-Pass"})
    ser, _ = _serial(relay)
    assert ser.elevate(1) is False
    assert relay.password_attempts == {"acc": ["OTTER"]}
    assert relay.cancels == 1
