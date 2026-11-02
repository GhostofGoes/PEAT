"""
Tests for the CIP Identity status/state decoding of the ControlLogix module.

The status words are synthetic, built from the bit definitions of the CIP
Identity object (ODVA CIP Vol. 1, Wireshark ``packet-cip.c``) and the Logix key
switch table of pycomm3 (``status = 0x3160`` is REMOTE + run mode + minor fault).
"""

from peat import ControlLogix, DeviceData
from peat.data.baseline import compare_device, split_path
from peat.modules.rockwell.clx_defaults import CLX_KNOWN_DEFAULTS
from peat.modules.rockwell.clx_identity import (
    apply_identity_status,
    decode_identity_status,
    most_severe_health,
)


def _by_name(indicators) -> dict:
    return {i.name: i for i in indicators}


def test_decode_worked_example_remote_run_minor_fault():
    decoded = decode_identity_status(0x3160, state=3, product_type="PLC")
    inds = _by_name(decoded.indicators)

    assert decoded.key_switch == "remote"
    assert inds["key_switch"].type == "switch"
    assert inds["key_switch"].category == "mode"
    assert inds["key_switch"].value == "REMOTE"
    assert inds["cip_extended_status"].value == "at least one I/O connection in run mode"
    assert inds["cip_extended_status"].type == "status_flag"
    assert inds["minor_recoverable_fault"].state == "on"
    assert inds["minor_recoverable_fault"].health == "maintenance_required"
    assert inds["minor_recoverable_fault"].category == "fault"
    assert inds["major_unrecoverable_fault"].state == "off"
    assert inds["major_unrecoverable_fault"].health == "normal"
    assert inds["owned"].state == "off"
    assert inds["owned"].health == ""
    assert inds["configured"].state == "off"
    assert inds["cip_state"].value == "Operational"
    assert decoded.status == "Operational"
    # The minor fault is more severe than "operational"
    assert decoded.health == "maintenance_required"
    # Every live reading has a timestamp and the raw status word
    for ind in decoded.indicators:
        assert ind.timestamp is not None
        assert ind.timestamp.tzinfo is not None
    assert inds["owned"].extra["status_word"] == "0x3160"


def test_decode_key_switch_only_for_plc():
    # The same bits on a communication module are vendor-specific
    decoded = decode_identity_status(0x3160, state=3, product_type="Communications Adapter")
    assert decoded.key_switch == ""
    assert "key_switch" not in _by_name(decoded.indicators)


def test_decode_program_mode_and_faults():
    # PROG key switch, all I/O connections idle (Logix program mode)
    decoded = decode_identity_status(0x2070, state=3, product_type="PLC")
    assert decoded.key_switch == "program"
    assert _by_name(decoded.indicators)["key_switch"].health == "check_function"
    assert decoded.health == "check_function"

    # RUN key switch, no faults
    decoded = decode_identity_status(0x1065, state=3, product_type="PLC")
    inds = _by_name(decoded.indicators)
    assert decoded.key_switch == "run"
    assert inds["owned"].state == "on"
    assert inds["configured"].state == "on"
    assert decoded.health == "normal"

    # Major fault wins over everything else
    decoded = decode_identity_status(0x2470, state=4, product_type="PLC")
    assert _by_name(decoded.indicators)["major_recoverable_fault"].state == "on"
    assert _by_name(decoded.indicators)["cip_state"].health == "failure"
    assert decoded.health == "failure"


def test_decode_unknown_state_and_missing_values():
    # No state: fault-free bits alone don't make the device "normal"
    decoded = decode_identity_status(0x0060, state=None, product_type="I/O")
    assert decoded.health == ""
    assert decoded.status == ""
    assert "cip_state" not in _by_name(decoded.indicators)

    decoded = decode_identity_status(None, state=255)
    inds = _by_name(decoded.indicators)
    assert list(inds) == ["cip_state"]
    assert inds["cip_state"].value == "unknown (255)"
    assert decoded.health == ""

    decoded = decode_identity_status(0x00A0, state=3)
    assert _by_name(decoded.indicators)["cip_extended_status"].value == "vendor specific"


def test_most_severe_health():
    assert most_severe_health() == ""
    assert most_severe_health("", "normal") == "normal"
    assert most_severe_health("normal", "maintenance_required", "check_function") == (
        "check_function"
    )
    assert most_severe_health("check_function", "failure") == "failure"


def test_apply_identity_status():
    dev = DeviceData(ip="192.0.2.10")
    apply_identity_status(dev, 0x3160, 3, "PLC")
    assert dev.key_switch == "remote"
    assert dev.health == "maintenance_required"
    assert dev.status == "Operational"
    assert dev.run_mode == ""  # never set from the identity status
    assert len(dev.indicators) == 9

    # A newer reading replaces the older one (same indicators, newest wins)
    apply_identity_status(dev, 0x1060, 3, "PLC")
    assert len(dev.indicators) == 9
    assert dev.key_switch == "run"
    assert dev.health == "normal"
    assert _by_name(dev.indicators)["key_switch"].value == "RUN"
    assert _by_name(dev.indicators)["minor_recoverable_fault"].state == "off"

    # An existing status is kept
    dev.status = "Run"
    apply_identity_status(dev, 0x1060, 3, "PLC")
    assert dev.status == "Run"


def _cip_values(product_type: str, status: int, state: int, serial: int) -> dict:
    return {
        "brand": "ControlLogix",
        "vendor": "Rockwell Automation/Allen-Bradley",
        "product_name": f"1756 {product_type}",
        "product_code": 166,
        "product_type": product_type,
        "serial_number": serial,
        "firmware_version": 32,
        "firmware_revision": 11,
        "state": state,
        "status": status,
    }


def test_extract_info_response_without_state_byte():
    import struct

    from peat.modules.rockwell.ab_scan import extract_info_response
    from peat.protocols.enip.enip_packets import GetAttributesAllResponse

    name = b"1756-IB16"
    raw = struct.pack("<HHHBBHIB", 1, 0x07, 1, 3, 1, 0x0060, 0x1, len(name)) + name
    info = extract_info_response(GetAttributesAllResponse(raw))
    assert info["state"] is None  # not "0" (Nonexistent)
    mod = DeviceData()
    ControlLogix._annotate_clx_values(mod, info)
    assert mod.status == ""
    assert not [i for i in mod.indicators if i.name == "cip_state"]

    assert extract_info_response(GetAttributesAllResponse(raw + b"\x03"))["state"] == 3


def test_controllogix_process_fingerprint(mocker, tmp_path):
    mocker.patch.object(DeviceData, "write_file", return_value=tmp_path / "x.json")
    dev = DeviceData(ip="192.0.2.10")
    result = {
        "modules": {
            0: _cip_values("PLC", 0x3160, 3, 1111),
            2: _cip_values("Communications Adapter", 0x3064, 3, 2222),
        }
    }
    ControlLogix._process_fingerprint(dev, result)

    assert "state" not in dev.extra
    assert "status" not in dev.extra
    assert dev.extra["product_code"] == 166
    assert dev.key_switch == "remote"
    assert dev.health == "maintenance_required"
    assert dev.type == "PLC"

    cpu = next(m for m in dev.module if m.slot == "0")
    comm = next(m for m in dev.module if m.slot == "2")
    assert cpu.key_switch == "remote"
    assert {i.name for i in cpu.indicators} >= {"key_switch", "cip_state"}
    assert comm.key_switch == ""
    assert "key_switch" not in {i.name for i in comm.indicators}
    assert _by_name(comm.indicators)["owned"].state == "off"
    assert comm.health == "normal"
    for mod in dev.module:
        assert "state" not in mod.extra
        assert "status" not in mod.extra


def test_controllogix_known_defaults():
    baselines = ControlLogix.get_known_defaults()
    assert [b.id for b in baselines] == ["clx-vendor-recommended"]
    assert baselines[0].kind == "vendor_recommended"
    assert baselines[0].selector.vendor_id == "Rockwell"
    assert baselines[0].selector.device_type == "PLC"
    rule_ids = [r.id for r in baselines[0].rules]
    assert "clx.key_switch.run" in rule_ids
    assert not any("configured" in r for r in rule_ids)
    for rule in baselines[0].rules:
        split_path(rule.path)

    def results(dev: DeviceData) -> dict:
        return {
            f.rule_id: f.result
            for f in compare_device(dev, CLX_KNOWN_DEFAULTS[0], include_passed=True)
        }

    dev = DeviceData(ip="192.0.2.10", type="PLC")
    dev.description.vendor.id = "Rockwell"
    apply_identity_status(dev, 0x1060, 3, "PLC")
    assert results(dev)["clx.key_switch.run"] == "pass"

    apply_identity_status(dev, 0x3060, 3, "PLC")
    assert results(dev)["clx.key_switch.run"] == "fail"

    ControlLogix._record_login(dev, "http", 80, "administrator", "")
    findings = compare_device(dev, CLX_KNOWN_DEFAULTS[0])
    cred = next(f for f in findings if f.rule_id == "clx.accounts.default-credentials")
    assert cred.result == "fail"
    assert cred.alert


def test_controllogix_factory_default_credentials():
    assert ControlLogix.is_factory_default_credential("Administrator", "")
    assert ControlLogix.is_factory_default_credential("administrator", "")
    assert not ControlLogix.is_factory_default_credential("Administrator", "secret")

    dev = DeviceData(ip="192.0.2.10")
    ControlLogix._record_login(dev, "ftp", 21, "Administrator", "")
    svc = dev.retrieve("service", {"protocol": "ftp"})
    assert svc.security.default_credentials is True
    assert svc.security.authentication_required is None

    # Site credentials: the factory default wasn't tested
    ControlLogix._record_login(dev, "http", 80, "engineer", "S3cret!")
    svc = dev.retrieve("service", {"protocol": "http"})
    assert svc.security.default_credentials is None
    assert svc.security.authentication_required is True
    assert "S3cret!" not in dev.json()
