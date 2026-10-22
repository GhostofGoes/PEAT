"""
Tests for parsing SEL relay settings files with the SELRelay module.

The sources and licenses of the data files are in data_files/relay/README.md.
"""

import shutil
from pathlib import Path

import pytest

from peat import SELRelay, config, datastore

RELAY_DIR = Path(__file__).resolve().parent / "data_files" / "relay"


@pytest.fixture(autouse=True)
def parse_env(tmp_path, mocker):
    mocker.patch.dict(
        config["CONFIG"],
        {
            "RUN_DIR": tmp_path,
            "DEVICE_DIR": tmp_path / "devices",
            "TEMP_DIR": tmp_path / "temp_results",
        },
    )
    # Prevent overwriting same device in the datastore with a different input file
    mocker.patch.object(datastore, "objects", [])
    return tmp_path


def _iface(dev, name):
    return next(i for i in dev.interface if i.name == name)


def _services(iface):
    return {s.protocol: s for s in iface.services}


# The real SEL-710 settings, in the different forms PEAT can parse
@pytest.mark.parametrize(
    "input_name",
    ["sel-710_Relay710.rdb", "sel-710_SET_ALL.TXT", "sel-710_rdb_streams"],
)
def test_parse_sel_710(input_name, caplog):
    dev = SELRelay.parse(RELAY_DIR / input_name)
    assert dev is not None

    assert dev.description.model == "710"
    assert dev.description.product == "SEL-710"
    assert dev.part_number == "071001A5X6X71821210"
    assert dev.firmware.id == "SEL-710-Rxxx-Vx-Z008004-Dxxxxxxxx"
    assert dev.firmware.release_date is None  # Masked in the QuickSet template
    assert dev.boot_firmware.id == "SLBT-710-Rxxx-V0-Z007004-Dxxxxxxxx"
    assert dev.ip == "192.168.1.2"
    assert dev.name == "sel-710"
    assert dev.extra["terminal_id"] == "motor_relay"
    assert dev.extra["relay_id_by_group"] == {"1": "SEL-710", "2": "SEL-710", "3": "SEL-710"}

    port_1 = _iface(dev, "Port 1")
    assert port_1.type == "ethernet"
    assert port_1.subnet_mask == "255.255.255.0"
    assert port_1.gateway == "192.168.1.1"
    svcs = _services(port_1)
    assert svcs["ftp"].enabled is True
    assert svcs["ftp"].extra["user"] == "FTPUSER"
    assert svcs["telnet"].port == 23
    assert svcs["sntp"].enabled is False  # ESNTP is "OFF"

    port_4 = _iface(dev, "Port 4")
    assert port_4.type == "serial"
    assert port_4.application == "dnet"
    assert port_4.baudrate == 19200
    assert port_4.stop_bits == 2

    # Modbus User Map ([M] section)
    modbus = [r for r in dev.registers if r.protocol == "modbus"]
    assert len(modbus) == 125
    mod_001 = next(r for r in modbus if r.name == "MOD_001")
    assert mod_001.address == "1"
    assert mod_001.io == "IA_MAG"

    parsed_logic = dev.logic.parsed
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in parsed_logic
    assert "OUT103=TRIP OR " in parsed_logic

    assert "Traceback" not in caplog.text
    assert "ERROR" not in caplog.text


def test_parse_rdb_extra_info(parse_env):
    dev = SELRelay.parse(RELAY_DIR / "sel-710_Relay710.rdb")

    assert dev.extra["rdb_relay_name"] == "New Settings 2"
    assert "Saved on 30/08/2025 at 3:33:00 PM" in dev.extra["SAVE_INFO_FROM_CLASSES"]
    assert dev.logic.created.year == 2025
    assert dev.logic.created.month == 8
    assert dev.logic.created.day == 30

    extracted = list(parse_env.rglob("extracted_SET_ALL.txt"))
    assert len(extracted) == 1
    assert extracted[0].read_text(encoding="utf-8").startswith("[INFO]")


STREAMS_DIR = RELAY_DIR / "sel-710_rdb_streams"


def _relay_files_layout(dst):
    """Lay out the SEL-710 streams like files downloaded from a relay over FTP."""
    (dst / "SETTINGS").mkdir(parents=True)
    shutil.copyfile(STREAMS_DIR / "Misc" / "Cfg.txt", dst / "CFG.TXT")
    for path in STREAMS_DIR.glob("set_*.txt"):
        shutil.copyfile(path, dst / "SETTINGS" / path.name.upper())
    return dst


def test_parse_relay_files_dir(tmp_path):
    # No SET_ALL.TXT, so it's reconstructed from CFG.TXT and SETTINGS/SET_*.TXT
    dev = SELRelay.parse(_relay_files_layout(tmp_path / "relay"))

    assert dev.description.model == "710"
    assert dev.ip == "192.168.1.2"
    assert dev.name == "sel-710"
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    assert len([r for r in dev.registers if r.protocol == "modbus"]) == 125


def test_parse_single_settings_file():
    dev = SELRelay.parse(STREAMS_DIR / "set_P1.txt")

    assert dev.ip == "192.168.1.2"
    assert dev.description.model == "710"
    assert _services(_iface(dev, "Port 1"))["telnet"].enabled is True
    assert not dev.registers


def test_parse_empty_dir(tmp_path):
    empty = tmp_path / "not_a_relay"
    empty.mkdir()
    (empty / "notes.txt").write_text("nothing to see here", encoding="utf-8")

    assert SELRelay.parse(empty) is None


def test_pull_configs_without_set_all(parse_env, mocker):
    # Relays without SET_ALL.TXT get it reconstructed from SET_*.TXT
    all_files = {}
    for path in [STREAMS_DIR / "Misc" / "Cfg.txt", *STREAMS_DIR.glob("set_*.txt")]:
        name = "CFG.TXT" if path.name == "Cfg.txt" else path.name.upper()
        all_files[name] = {
            "name": name,
            "data": path.read_text(encoding="utf-8"),
            "device_path": f"/SETTINGS/{name}",
            "local_path": None,
        }
    mocker.patch("peat.modules.sel.sel_relay.pull_files", return_value=all_files)

    dev = datastore.get("192.168.1.2", "ip")
    assert SELRelay.pull_configs(dev, comms=None) is True

    assert dev.name == "sel-710"
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed
    assert _iface(dev, "Port 1").ip == "192.168.1.2"
    assert list(parse_env.rglob("combined_SET_ALL.txt"))


def test_parse_dir_multiple_relays(tmp_path):
    relays = tmp_path / "relays"
    relays.mkdir()
    _relay_files_layout(relays / "relay_a")
    # A second relay, with a different IP address
    (relays / "relay_b").mkdir()
    p1 = (STREAMS_DIR / "set_P1.txt").read_bytes()
    (relays / "relay_b" / "SET_P5.TXT").write_bytes(
        p1.replace(b"[P1]", b"[P5]").replace(b"192.168.1.2", b"192.168.1.3")
    )
    # Not a relay's filename, parsed by itself
    shutil.copyfile(RELAY_DIR / "sel-710_Relay710.rdb", relays / "relay_c.rdb")

    dev = SELRelay.parse(relays)

    assert dev is not None
    ips = {d.ip for d in datastore.objects}
    assert {"192.168.1.2", "192.168.1.3"} <= ips
    # The other relays are exported too
    assert (tmp_path / "devices" / "192.168.1.3" / "device-data-summary.json").is_file()


def test_parse_dir_empty_set_all(tmp_path):
    relay = _relay_files_layout(tmp_path / "relay")
    (relay / "SET_ALL.TXT").write_bytes(b"=>")  # What a failed download looks like

    dev = SELRelay.parse(relay)

    assert dev.ip == "192.168.1.2"
    assert "TR=49T OR LOSSTRIP OR JAMTRIP" in dev.logic.parsed


def test_parse_dir_garbage_cfg(tmp_path):
    relay = tmp_path / "relay"
    relay.mkdir()
    (relay / "CFG.TXT").write_text("hello world", encoding="utf-8")

    assert SELRelay.parse(relay) is None


def test_parse_not_settings(tmp_path):
    path = tmp_path / "OFFSET_1.TXT"
    path.write_text("Some notes, not settings\r\n", encoding="utf-8")

    assert SELRelay.parse(path) is None


def test_parse_rdb_multiple_relays_same_ip(tmp_path, mocker):
    set_all = (RELAY_DIR / "sel-710_SET_ALL.TXT").read_text(encoding="utf-8")
    mocker.patch(
        "peat.modules.sel.sel_relay.parse_rdb_relays",
        return_value={"Motor A": set_all, "Motor B": set_all.replace("MOTOR RELAY", "MOTOR B")},
    )

    dev = SELRelay.parse(RELAY_DIR / "sel-710_Relay710.rdb")

    assert dev.extra["rdb_relay_name"] == "Motor A"
    assert dev.extra["terminal_id"] == "motor_relay"
    other = next(d for d in datastore.objects if d.extra.get("rdb_relay_name") == "Motor B")
    assert other is not dev
    assert other.id == "sel-710_Relay710_Motor B"
    assert other.extra["terminal_id"] == "motor_b"
    assert list((tmp_path / "devices").rglob("extracted_SET_ALL.txt"))
